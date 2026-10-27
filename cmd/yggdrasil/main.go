package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"suah.dev/protect"

	"github.com/gologme/log"
	gsyslog "github.com/hashicorp/go-syslog"
	"github.com/hjson/hjson-go/v4"
	"github.com/kardianos/minwinsvc"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlicproxy"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/dashboard"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"github.com/yggdrasil-network/yggdrasil-go/src/tun"
	"github.com/yggdrasil-network/yggdrasil-go/src/version"
)

type node struct {
	core        *core.Core
	tun         *tun.TunAdapter
	multicast   *multicast.Multicast
	admin       *admin.AdminSocket
	garlic      *garlic.Garlic
	garlicProxy *garlicproxy.Proxy
	dashboard   *dashboard.Process
}

// The main function is responsible for configuring and starting Yggdrasil.
func main() {
	genconf := flag.Bool("genconf", false, "print a new config to stdout")
	useconf := flag.Bool("useconf", false, "read HJSON/JSON config from stdin")
	useconffile := flag.String("useconffile", "", "read HJSON/JSON config from specified file path")
	normaliseconf := flag.Bool("normaliseconf", false, "use in combination with either -useconf or -useconffile, outputs your configuration normalised")
	exportkey := flag.Bool("exportkey", false, "use in combination with either -useconf or -useconffile, outputs your private key in PEM format")
	confjson := flag.Bool("json", false, "print configuration from -genconf or -normaliseconf as JSON instead of HJSON")
	autoconf := flag.Bool("autoconf", false, "automatic mode (dynamic IP, peer with IPv6 neighbors)")
	ver := flag.Bool("version", false, "prints the version of this build")
	logto := flag.String("logto", "stdout", "file path to log to, \"syslog\" or \"stdout\"")
	getaddr := flag.Bool("address", false, "use in combination with either -useconf or -useconffile, outputs your IPv6 address")
	getsnet := flag.Bool("subnet", false, "use in combination with either -useconf or -useconffile, outputs your IPv6 subnet")
	getpkey := flag.Bool("publickey", false, "use in combination with either -useconf or -useconffile, outputs your public key")
	loglevel := flag.String("loglevel", "info", "loglevel to enable")
	chuserto := flag.String("user", "", "user (and, optionally, group) to set UID/GID to")
	notifyFd := flag.Int("notifyfd", -1, "write a newline to this file-descriptor to indicate readiness to a service manager")
	flag.Parse()

	done := make(chan struct{})
	defer close(done)

	// Catch interrupts from the operating system to exit gracefully.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// Create a new logger that logs output to stdout.
	var logger *log.Logger
	switch *logto {
	case "stdout":
		logger = log.New(os.Stdout, "", log.Flags())

	case "syslog":
		if syslogger, err := gsyslog.NewLogger(gsyslog.LOG_NOTICE, "DAEMON", version.BuildName()); err == nil {
			logger = log.New(syslogger, "", log.Flags()&^(log.Ldate|log.Ltime))
		}

	default:
		if logfd, err := os.OpenFile(*logto, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			logger = log.New(logfd, "", log.Flags())
		}
	}
	if logger == nil {
		logger = log.New(os.Stdout, "", log.Flags())
		logger.Warnln("Logging defaulting to stdout")
	}
	if *normaliseconf {
		setLogLevel("error", logger)
	} else {
		setLogLevel(*loglevel, logger)
	}

	cfg := config.GenerateConfig()
	var err error
	switch {
	case *ver:
		fmt.Println("Build name:", version.BuildName())
		fmt.Println("Build version:", version.BuildVersion())
		return

	case *autoconf:
		// Use an autoconf-generated config, this will give us random keys and
		// port numbers, and will use an automatically selected TUN interface.

	case *useconf:
		if _, err := cfg.ReadFrom(os.Stdin); err != nil {
			panic(err)
		}

	case *useconffile != "":
		f, err := os.Open(*useconffile)
		if err != nil {
			panic(err)
		}
		if _, err := cfg.ReadFrom(f); err != nil {
			panic(err)
		}
		_ = f.Close()

	case *genconf:
		// Generated files contain independent persistent Garlic secrets so
		// enabling hosting later does not create a new domain on each boot.
		identity, genErr := garlic.NewIdentity()
		if genErr != nil {
			panic(genErr)
		}
		cfg.Garlic.PrivateKey = identity.PrivateKey
		cfg.Garlic.SigningPrivateKey = identity.SigningPrivateKey.Seed()
		cfg.AdminListen = ""
		var bs []byte
		if *confjson {
			bs, err = json.MarshalIndent(cfg, "", "  ")
		} else {
			bs, err = hjson.Marshal(cfg)
		}
		if err != nil {
			panic(err)
		}
		fmt.Println(string(bs))
		return

	default:
		fmt.Println("Usage:")
		flag.PrintDefaults()

		if *getaddr || *getsnet {
			fmt.Println("\nError: You need to specify some config data using -useconf or -useconffile.")
		}
		return
	}

	privateKey := ed25519.PrivateKey(cfg.PrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	switch {
	case *getaddr:
		addr := address.AddrForKey(publicKey)
		ip := net.IP(addr[:])
		fmt.Println(ip.String())
		return

	case *getsnet:
		snet := address.SubnetForKey(publicKey)
		ipnet := net.IPNet{
			IP:   append(snet[:], 0, 0, 0, 0, 0, 0, 0, 0),
			Mask: net.CIDRMask(len(snet)*8, 128),
		}
		fmt.Println(ipnet.String())
		return

	case *getpkey:
		fmt.Println(hex.EncodeToString(publicKey))
		return

	case *normaliseconf:
		cfg.AdminListen = ""
		if cfg.PrivateKeyPath != "" {
			cfg.PrivateKey = nil
		}
		var bs []byte
		if *confjson {
			bs, err = json.MarshalIndent(cfg, "", "  ")
		} else {
			bs, err = hjson.Marshal(cfg)
		}
		if err != nil {
			panic(err)
		}
		fmt.Println(string(bs))
		return

	case *exportkey:
		pem, err := cfg.MarshalPEMPrivateKey()
		if err != nil {
			panic(err)
		}
		fmt.Println(string(pem))
		return
	}

	n := &node{}

	// Set up the Yggdrasil node itself.
	{
		iprange := net.IPNet{
			IP:   net.ParseIP("200::"),
			Mask: net.CIDRMask(7, 128),
		}
		options := []core.SetupOption{
			core.NodeInfo(cfg.NodeInfo),
			core.NodeInfoPrivacy(cfg.NodeInfoPrivacy),
			core.PeerFilter(func(ip net.IP) bool {
				return !iprange.Contains(ip)
			}),
		}
		for _, addr := range cfg.Listen {
			options = append(options, core.ListenAddress(addr))
		}
		for _, peer := range cfg.Peers {
			options = append(options, core.Peer{URI: peer})
		}
		if cfg.GroupPassword != "" {
			options = append(options, core.GroupPassword(cfg.GroupPassword))
		}
		for intf, peers := range cfg.InterfacePeers {
			for _, peer := range peers {
				options = append(options, core.Peer{URI: peer, SourceInterface: intf})
			}
		}
		for _, allowed := range cfg.AllowedPublicKeys {
			k, err := hex.DecodeString(allowed)
			if err != nil {
				panic(err)
			}
			options = append(options, core.AllowedPublicKey(k[:]))
		}
		if n.core, err = core.New(cfg.Certificate, logger, options...); err != nil {
			panic(err)
		}
		address, subnet := n.core.Address(), n.core.Subnet()
		logger.Printf("Your public key is %s", hex.EncodeToString(n.core.PublicKey()))
		logger.Printf("Your IPv6 address is %s", address.String())
		logger.Printf("Your IPv6 subnet is %s", subnet.String())
	}

	// Set up the admin socket.
	{
		options := []admin.SetupOption{
			admin.ListenAddress(cfg.AdminListen),
		}
		if cfg.LogLookups {
			options = append(options, admin.LogLookups{})
		}
		if n.admin, err = admin.New(n.core, logger, options...); err != nil {
			panic(err)
		}
		if n.admin != nil {
			n.admin.SetupAdminHandlers()
		}
	}

	// Set up the multicast module.
	{
		options := []multicast.SetupOption{}
		for _, intf := range cfg.MulticastInterfaces {
			options = append(options, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}
		if n.multicast, err = multicast.New(n.core, logger, options...); err != nil {
			panic(err)
		}
		if n.admin != nil && n.multicast != nil {
			n.multicast.SetupAdminHandlers(n.admin)
		}
	}

	// Set up the TUN module.
	{
		options := []tun.SetupOption{
			tun.InterfaceName(cfg.IfName),
			tun.InterfaceMTU(cfg.IfMTU),
		}
		if n.tun, err = tun.New(ipv6rwc.NewReadWriteCloser(n.core), logger, options...); err != nil {
			panic(err)
		}
		if n.admin != nil && n.tun != nil {
			n.tun.SetupAdminHandlers(n.admin)
		}
	}

	// Set up the Garlic Routing Overlay (experimental, optional). When
	// cfg.Garlic.Enabled is false (the default), this block does nothing
	// and n.garlic stays nil - behavior is identical to a build with no
	// Garlic support at all. See docs/garlic-architecture.md.
	{
		if cfg.Garlic.Enabled {
			var identity *garlic.Identity
			switch {
			case len(cfg.Garlic.PrivateKey) > 0 && len(cfg.Garlic.SigningPrivateKey) > 0:
				if identity, err = garlic.LoadIdentityFromPrivateKeys(cfg.Garlic.PrivateKey, cfg.Garlic.SigningPrivateKey); err != nil {
					panic(err)
				}
			case len(cfg.Garlic.PrivateKey) > 0:
				// Upgrade path: a node that was already running Garlic
				// before Garlic.SigningPrivateKey existed has
				// Garlic.PrivateKey configured but not the new signing
				// key. Keep the existing X25519 identity stable and
				// generate only a fresh signing identity for this run -
				// regenerating both would silently reset an already-
				// stable Garlic identity on every restart, not just add
				// a new one.
				if identity, err = garlic.LoadIdentityFromPrivateKey(cfg.Garlic.PrivateKey); err != nil {
					panic(err)
				}
				logger.Warnln("Garlic.PrivateKey configured but no Garlic.SigningPrivateKey - generated a fresh signing identity for this run only; your Garlic X25519 identity remains stable")
			case len(cfg.Garlic.SigningPrivateKey) > 0:
				_, privateKey, keyErr := garlic.GenerateKeypair()
				if keyErr != nil {
					panic(keyErr)
				}
				identity, err = garlic.LoadIdentityFromPrivateKeys(privateKey, cfg.Garlic.SigningPrivateKey)
				if err != nil {
					panic(err)
				}
				logger.Warnln("No Garlic.PrivateKey configured - generated an ephemeral X25519 key; the configured signing key keeps your domains stable")
			default:
				if identity, err = garlic.NewIdentity(); err != nil {
					panic(err)
				}
				logger.Warnln("No Garlic.PrivateKey/SigningPrivateKey configured - generated ephemeral Garlic identity keys for this run only")
			}
			lifetime, err := time.ParseDuration(cfg.Garlic.CircuitLifetime)
			if err != nil {
				panic(fmt.Sprintf("invalid Garlic.CircuitLifetime %q: %v", cfg.Garlic.CircuitLifetime, err))
			}
			gcfg := garlic.DefaultConfig()
			gcfg.PathLength = cfg.Garlic.PathLength
			gcfg.CircuitLifetime = lifetime
			gcfg.MaxCircuits = cfg.Garlic.MaxCircuits
			gcfg.MaxCircuitsPerPeer = cfg.Garlic.MaxCircuitsPerPeer
			gcfg.MaxRelayCircuits = cfg.Garlic.MaxRelayCircuits
			gcfg.PaddingEnabled = cfg.Garlic.Padding.Enabled
			gcfg.MinPaddedSize = cfg.Garlic.Padding.MinSize
			gcfg.MaxPaddedSize = cfg.Garlic.Padding.MaxSize
			gcfg.JitterEnabled = cfg.Garlic.Jitter.Enabled
			if gcfg.MinJitter, err = time.ParseDuration(cfg.Garlic.Jitter.MinDelay); err != nil {
				panic(fmt.Sprintf("invalid Garlic.Jitter.MinDelay %q: %v", cfg.Garlic.Jitter.MinDelay, err))
			}
			if gcfg.MaxJitter, err = time.ParseDuration(cfg.Garlic.Jitter.MaxDelay); err != nil {
				panic(fmt.Sprintf("invalid Garlic.Jitter.MaxDelay %q: %v", cfg.Garlic.Jitter.MaxDelay, err))
			}
			gcfg.MaxDiscoveredPeers = cfg.Garlic.MaxDiscoveredPeers
			gcfg.MinHopCount = cfg.Garlic.MinHopCount
			gcfg.BootstrapPeers = cfg.Garlic.BootstrapPeers
			gcfg.AutoPoolEnabled = cfg.Garlic.AutoPoolEnabled
			gcfg.AutoPoolSize = cfg.Garlic.AutoPoolSize
			if gcfg.AutoRotationInterval, err = time.ParseDuration(cfg.Garlic.AutoRotationInterval); err != nil {
				panic(fmt.Sprintf("invalid Garlic.AutoRotationInterval %q: %v", cfg.Garlic.AutoRotationInterval, err))
			}
			gcfg.CoverTrafficEnabled = cfg.Garlic.CoverTrafficEnabled
			if gcfg.CoverTrafficInterval, err = time.ParseDuration(cfg.Garlic.CoverTrafficInterval); err != nil {
				panic(fmt.Sprintf("invalid Garlic.CoverTrafficInterval %q: %v", cfg.Garlic.CoverTrafficInterval, err))
			}
			n.garlic = garlic.New(n.core, identity, gcfg, nil)
			logger.Printf("Your Garlic public key is %s", hex.EncodeToString(identity.PublicKey))
			logger.Printf("Your Garlic default domain is %s", garlic.ComputeGID(identity.SigningPublicKey, nil).Domain())
			if n.admin != nil {
				n.garlic.SetupAdminHandlers(n.admin)
			}
			if cfg.Garlic.Proxy.Enabled {
				n.garlicProxy, err = garlicproxy.Start(n.garlic, cfg.Garlic.Proxy.Listen)
				if err != nil {
					panic(err)
				}
				logger.Printf("Garlic browser proxy: http://%s (PAC: http://%s/proxy.pac)", n.garlicProxy.Addr(), n.garlicProxy.Addr())
			}
			for _, service := range cfg.Garlic.Services {
				host, err := n.garlic.StartService(garlic.ServiceConfig{ServiceID: service.ServiceID, LocalAddr: service.LocalAddr, TLSLocalAddr: service.TLSLocalAddr})
				if err != nil {
					panic(err)
				}
				logger.Printf("Garlic website starting: http://%s/", host.Domain())
				go func() {
					select {
					case <-host.Ready():
						logger.Printf("Garlic website published: http://%s/", host.Domain())
					case <-ctx.Done():
					}
				}()
			}
		}
	}

	// Set up the local operator dashboard (optional, disabled by
	// default). A failure here is always a warning, never fatal - the
	// dashboard must never be the reason yggdrasil itself won't start.
	{
		if cfg.Dashboard.Enabled {
			dcfg := dashboard.Config{
				Listen:      cfg.Dashboard.Listen,
				Path:        cfg.Dashboard.Path,
				AdminListen: cfg.AdminListen,
			}
			if n.dashboard, err = dashboard.Start(dcfg, logger); err != nil {
				logger.Warnln("Dashboard not started:", err)
			}
		}
	}

	//Windows service shutdown
	minwinsvc.SetOnExit(func() {
		logger.Infof("Shutting down service ...")
		cancel()
		// Wait for all parts to shutdown properly
		<-done
	})

	// Change user if requested
	if *chuserto != "" {
		err = chuser(*chuserto, cfg.AdminListen)
		if err != nil {
			panic(err)
		}
	}

	// Promise final modes of operation.  At this point, if at all:
	// - raw socket is created/open
	// - admin socket is created/open
	// - privileges are dropped to non-root user
	//
	// Peers, InterfacePeers, Listen can be UNIX sockets;
	// Go's net.Listen.Close() deletes files on shutdown.
	promises := []string{"stdio", "rpath", "cpath", "inet", "unix", "dns"}
	if len(cfg.MulticastInterfaces) > 0 {
		promises = append(promises, "mcast")
	}
	if cfg.Dashboard.Enabled {
		// Only relevant on OpenBSD, where protect.Pledge actually
		// enforces this - "proc" is needed to signal/wait on the
		// already-spawned dashboard child process at shutdown. The
		// exec() itself already happened above, before this pledge
		// call, so "exec" doesn't need to be a standing promise.
		promises = append(promises, "proc")
	}
	if err := protect.Pledge(strings.Join(promises, " ")); err != nil {
		panic(fmt.Sprintf("pledge: %v: %v", promises, err))
	}

	if notifyFd != nil && *notifyFd > 0 {
		f := os.NewFile(uintptr(*notifyFd), "notifyfd")
		_, _ = f.Write([]byte{0x0a})
		f.Close()
	}

	// Block until we are told to shut down.
	<-ctx.Done()

	// Shut down the node.
	if n.dashboard != nil {
		_ = n.dashboard.Stop()
	}
	if n.garlicProxy != nil {
		_ = n.garlicProxy.Close()
	}
	if n.garlic != nil {
		n.garlic.Close()
	}
	_ = n.admin.Stop()
	_ = n.multicast.Stop()
	_ = n.tun.Stop()
	n.core.Stop()
}

func setLogLevel(loglevel string, logger *log.Logger) {
	levels := [...]string{"error", "warn", "info", "debug", "trace"}
	loglevel = strings.ToLower(loglevel)

	contains := func() bool {
		for _, l := range levels {
			if l == loglevel {
				return true
			}
		}
		return false
	}

	if !contains() { // set default log level
		logger.Infoln("Loglevel parse failed. Set default level(info)")
		loglevel = "info"
	}

	for _, l := range levels {
		logger.EnableLevel(l)
		if l == loglevel {
			break
		}
	}
}
