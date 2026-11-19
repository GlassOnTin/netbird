package rosenpass

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// NetstackRegistrar is the firewall subset needed to route inbound Rosenpass
// packets to an in-stack listener (implemented by uspfilter.Manager). Mirrors
// the dnsfwd netstack-service registration (#662 phase 2).
type NetstackRegistrar interface {
	RegisterNetstackService(protocol nftypes.Protocol, port uint16)
	UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
}

const (
	defaultLog         = slog.LevelInfo
	defaultLogLevelVar = "NB_ROSENPASS_LOG_LEVEL"
)

func hashRosenpassKey(key []byte) string {
	hasher := sha256.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

// rpServer is the subset of rp.Server used by Manager. Defined as an interface
// so tests can substitute a mock without spinning up a real UDP server.
type rpServer interface {
	AddPeer(rp.PeerConfig) (rp.PeerID, error)
	RemovePeer(rp.PeerID) error
	Run() error
	Close() error
}

type Manager struct {
	ifaceName    string
	localWgKey   wgtypes.Key
	spk          []byte
	ssk          []byte
	rpKeyHash    string
	preSharedKey *[32]byte
	rpPeerIDs    map[string]*rp.PeerID
	rpWgHandler  *NetbirdHandler
	server       rpServer
	lock         sync.Mutex
	port         int
	wgIface      PresharedKeySetter

	// #662 phase 2: in netstack mode the Rosenpass UDP transport must bind
	// inside gvisor netstack (not on the host) so android-initiated handshakes
	// reach the peer overlay IP. The bind is deferred to interface-up because
	// Run() executes before the WireGuard interface (and its GetNet()) exists.
	fw             NetstackRegistrar
	pendingCfg     *rp.Config
	rpConn         rp.Conn
	registeredPort int
}

// NewManager creates a new Rosenpass manager. localWgKey is the local
// WireGuard public key, used to derive the per-peer rendezvous key.
func NewManager(preSharedKey *wgtypes.Key, wgIfaceName string, localWgKey wgtypes.Key) (*Manager, error) {
	public, secret, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	rpKeyHash := hashRosenpassKey(public)
	log.Tracef("generated new rosenpass key pair with public key %s", rpKeyHash)
	return &Manager{
		ifaceName:    wgIfaceName,
		localWgKey:   localWgKey,
		rpKeyHash:    rpKeyHash,
		spk:          public,
		ssk:          secret,
		preSharedKey: (*[32]byte)(preSharedKey),
		rpPeerIDs:    make(map[string]*rp.PeerID),
		// rpWgHandler is created here (instead of only in generateConfig) so it
		// is never nil between NewManager and Run(). Otherwise an early
		// OnConnected call (race observed on Android, issue #4341) panics on
		// nil receiver in addPeer -> m.rpWgHandler.AddPeer. generateConfig will
		// replace it with a fresh handler on each Run() to clear stale peer
		// state from previous engine sessions.
		rpWgHandler: NewNetbirdHandler((*[32]byte)(preSharedKey), localWgKey),
		lock:        sync.Mutex{},
	}, nil
}

func (m *Manager) GetPubKey() []byte {
	return m.spk
}

// GetAddress returns the address of the Rosenpass server
func (m *Manager) GetAddress() *net.UDPAddr {
	return &net.UDPAddr{Port: m.port}
}

// addPeer adds a new peer to the Rosenpass server
func (m *Manager) addPeer(rosenpassPubKey []byte, rosenpassAddr string, wireGuardIP string, wireGuardPubKey string) error {
	// Defense in depth against issue #4341 (Android crash): if Run() has not
	// completed yet, m.server / m.rpWgHandler may be nil. Return an explicit
	// error instead of panicking on nil-receiver dereference.
	if m.server == nil {
		return fmt.Errorf("rosenpass server not initialized")
	}
	if m.rpWgHandler == nil {
		return fmt.Errorf("rosenpass wg handler not initialized")
	}

	var err error
	pcfg := rp.PeerConfig{PublicKey: rosenpassPubKey}
	if m.preSharedKey != nil {
		pcfg.PresharedKey = *m.preSharedKey
	}
	if bytes.Compare(m.spk, rosenpassPubKey) == 1 {
		_, strPort, err := net.SplitHostPort(rosenpassAddr)
		if err != nil {
			return fmt.Errorf("failed to parse rosenpass address: %w", err)
		}
		peerAddr := net.JoinHostPort(wireGuardIP, strPort)
		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
			return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
		}
		// Our local Rosenpass UDP server binds on the IPv6 wildcard ([::]) — see
		// GetAddress(). The remote peer's endpoint (pcfg.Endpoint) is the destination
		// our server will sendto when initiating handshakes. ResolveUDPAddr returns a
		// 4-byte IPv4 for IPv4 hosts, which the kernel rejects (EDESTADDRREQ) when
		// sent from an AF_INET6 socket. Normalize the remote endpoint to IPv4-mapped
		// IPv6 so its address family matches our listening socket.
		// TODO: maybe bind the Rosenpass UDP server to the peer wg IP addr
		if v4 := pcfg.Endpoint.IP.To4(); v4 != nil {
			pcfg.Endpoint.IP = v4.To16()
		}
	}
	peerID, err := m.server.AddPeer(pcfg)
	if err != nil {
		return err
	}

	key, err := wgtypes.ParseKey(wireGuardPubKey)
	if err != nil {
		return err
	}
	m.rpWgHandler.AddPeer(peerID, m.ifaceName, rp.Key(key))
	m.rpPeerIDs[wireGuardPubKey] = &peerID
	return nil
}

// removePeer removes a peer from the Rosenpass server
func (m *Manager) removePeer(wireGuardPubKey string) error {
	err := m.server.RemovePeer(*m.rpPeerIDs[wireGuardPubKey])
	if err != nil {
		return err
	}
	m.rpWgHandler.RemovePeer(*m.rpPeerIDs[wireGuardPubKey])
	return nil
}

func (m *Manager) generateConfig() (rp.Config, error) {
	opts := &slog.HandlerOptions{
		Level: getLogLevel(),
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	cfg := rp.Config{Logger: logger}

	cfg.PublicKey = m.spk
	cfg.SecretKey = m.ssk

	cfg.Peers = []rp.PeerConfig{}

	m.lock.Lock()
	m.rpWgHandler = NewNetbirdHandler(m.preSharedKey, m.localWgKey)
	if m.wgIface != nil {
		m.rpWgHandler.SetInterface(m.wgIface)
	}
	m.lock.Unlock()

	cfg.Handlers = []rp.Handler{m.rpWgHandler}

	port, err := findRandomAvailableUDPPort()
	if err != nil {
		log.Errorf("could not determine a random port for rosenpass server. Error: %s", err)
		return rp.Config{}, err
	}

	m.port = port

	cfg.ListenAddrs = []*net.UDPAddr{m.GetAddress()}

	return cfg, nil
}

func getLogLevel() slog.Level {
	level, ok := os.LookupEnv(defaultLogLevelVar)
	if !ok {
		return defaultLog
	}
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		log.Warnf("unknown log level: %s. Using default %s", level, defaultLog.String())
		return defaultLog
	}
}

func (m *Manager) OnDisconnected(peerKey string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.rpPeerIDs[peerKey]; !ok {
		// if we didn't have this peer yet, just skip
		return
	}

	err := m.removePeer(peerKey)
	if err != nil {
		log.Error("failed to remove rosenpass peer", err)
	}

	delete(m.rpPeerIDs, peerKey)
}

// Run configures the Rosenpass server. The socket bind is deferred to
// SetInterface (interface-up): in netstack mode the transport must bind inside
// gvisor netstack via wgIface.GetNet(), which does not exist yet at Run() time
// (the engine calls Run before wgInterfaceCreate/Up). If the interface was
// already set, start immediately. (#662 phase 2)
func (m *Manager) Run() error {
	conf, err := m.generateConfig()
	if err != nil {
		return err
	}

	m.lock.Lock()
	iface := m.wgIface
	if iface == nil {
		m.pendingCfg = &conf
	}
	m.lock.Unlock()

	if iface != nil {
		return m.startServer(&conf, iface)
	}

	log.Infof("rosenpass configured on port %d; bind deferred to interface-up", m.port)
	return nil
}

// SetFirewall provides the netstack-service registrar (the engine's firewall).
// Call before SetInterface so the in-stack bind can register inbound routing.
func (m *Manager) SetFirewall(fw NetstackRegistrar) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.fw = fw
}

// startServer binds the Rosenpass transport and starts the server. In netstack
// mode (iface.GetNet() != nil) it binds an in-stack gonet.UDPConn through the
// go-rosenpass socket-injection hook and registers the inbound UDP service so
// both initiation directions route through the tunnel overlay. Otherwise it
// binds a host socket (original behaviour). (#662 phase 2)
func (m *Manager) startServer(cfg *rp.Config, iface PresharedKeySetter) error {
	var nsnet *netstack.Net
	if ni, ok := iface.(interface{ GetNet() *netstack.Net }); ok {
		nsnet = ni.GetNet()
	}

	var conn rp.Conn
	if nsnet != nil {
		udpConn, err := rp.NewUDPConnWithListenFunc(cfg.ListenAddrs, func(_ string, addr *net.UDPAddr) (net.PacketConn, error) {
			return nsnet.ListenUDP(addr)
		})
		if err != nil {
			return fmt.Errorf("create in-stack rosenpass conn: %w", err)
		}
		conn = udpConn
	} else {
		udpConn, err := rp.NewUDPConn(cfg.ListenAddrs)
		if err != nil {
			return fmt.Errorf("create rosenpass conn: %w", err)
		}
		conn = udpConn
	}

	cfg.Conn = conn
	server, err := rp.NewServer(*cfg)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create rosenpass server: %w", err)
	}

	m.lock.Lock()
	m.server = server
	m.rpConn = conn
	fw := m.fw
	m.lock.Unlock()

	if nsnet != nil && fw != nil {
		fw.RegisterNetstackService(nftypes.UDP, uint16(m.port))
		m.lock.Lock()
		m.registeredPort = m.port
		m.lock.Unlock()
		log.Infof("starting rosenpass server in-stack on UDP:%d (netstack)", m.port)
	} else {
		log.Infof("starting rosenpass server on host port %d", m.port)
	}

	return server.Run()
}

// Close closes the Rosenpass server and its transport socket.
func (m *Manager) Close() error {
	m.lock.Lock()
	server := m.server
	m.server = nil
	conn := m.rpConn
	m.rpConn = nil
	fw := m.fw
	regPort := m.registeredPort
	m.registeredPort = 0
	m.pendingCfg = nil
	m.lock.Unlock()

	if fw != nil && regPort != 0 {
		fw.UnregisterNetstackService(nftypes.UDP, uint16(regPort))
	}
	if server != nil {
		if err := server.Close(); err != nil {
			log.Errorf("failed closing local rosenpass server: %v", err)
		}
	}
	// cfg.Conn is supplied externally, so rp.Server.Close() (closeConn=false)
	// does not close it; close the transport socket here. (#662 phase 2)
	if conn != nil {
		if err := conn.Close(); err != nil {
			log.Errorf("failed closing rosenpass transport: %v", err)
		}
	}
	return nil
}

// SetInterface sets the WireGuard interface for the rosenpass handler.
// This can be called before or after Run() - the interface will be stored
// and passed to the handler when it's created or updated immediately if
// already running.
func (m *Manager) SetInterface(iface PresharedKeySetter) {
	m.lock.Lock()
	m.wgIface = iface
	if m.rpWgHandler != nil {
		m.rpWgHandler.SetInterface(iface)
	}
	pending := m.pendingCfg
	m.pendingCfg = nil
	m.lock.Unlock()

	// Interface is up now (GetNet available in netstack mode): perform the
	// deferred Rosenpass bind. (#662 phase 2)
	if pending != nil {
		if err := m.startServer(pending, iface); err != nil {
			log.Errorf("failed to start rosenpass server at interface-up: %v", err)
		}
	}
}

// OnConnected is a handler function that is triggered when a connection to a remote peer establishes
func (m *Manager) OnConnected(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if remoteRosenpassPubKey == nil {
		log.Warnf("remote peer with public key %s does not support rosenpass", remoteWireGuardKey)
		return
	}

	rpKeyHash := hashRosenpassKey(remoteRosenpassPubKey)
	log.Debugf("received remote rosenpass key %s, my key %s", rpKeyHash, m.rpKeyHash)

	err := m.addPeer(remoteRosenpassPubKey, remoteRosenpassAddr, wireGuardIP, remoteWireGuardKey)
	if err != nil {
		log.Errorf("failed to add rosenpass peer: %s", err)
		return
	}
}

// IsPresharedKeyInitialized returns true if Rosenpass has completed a handshake
// and set a PSK for the given WireGuard peer.
func (m *Manager) IsPresharedKeyInitialized(wireGuardPubKey string) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	peerID, ok := m.rpPeerIDs[wireGuardPubKey]
	if !ok || peerID == nil {
		return false
	}

	return m.rpWgHandler.IsPeerInitialized(*peerID)
}

func findRandomAvailableUDPPort() (int, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, fmt.Errorf("could not find an available UDP port: %w", err)
	}
	defer conn.Close()

	_, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return 0, fmt.Errorf("parse local address %s: %w", conn.LocalAddr(), err)
	}
	return strconv.Atoi(portStr)
}
