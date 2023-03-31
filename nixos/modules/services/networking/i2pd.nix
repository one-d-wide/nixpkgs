{ config, lib, pkgs, ... }:

with lib;

let

  /* Configuration Generator (ini-like, lowercase-default)
  *
  * Automatic generation is achieved by attaching persing meta information
  * to all option definitions (`options.services.i2pd.**.${metaAttrName}.(metaAttr)`).
  *
  * I2pd config has several types of nesting (ways to interpret modules's options):
  *
  * "Direct":
  *   `some_option`           - No nesting, value is final (`direct...`)
  *   `[section]\n...`        - Nested attributes are INI field (`directSection...`)
  *   `(prefix).some_option`  - Recursively apply prefix to all sub-attributes (`directPrefix...`)
  *
  * "Indirect":
  *   Ignore    - Option is not in i2pd config (`directIgnore`)
  *   Special   - Option requires special interpreting (`directSpecial`)
  *
  * Note: If no alias specified, option name will be inferred
  *       from attrubute name by applying `string.toLower`,
  *       use `...NoLower` to preserve case.
  */
  metaAttrName = "i2pdConfigMetaData";
  directMeta = name: value: { ${metaAttrName}.${name} = value; }; # Specify parsing meta info

  direct                     = directMeta "option"          null; # Option name is inferred (after `toLower`)
  directNoLower              = directMeta "optionNoLower"   null;
  directAlias         = alias: directMeta "optionAlias"     alias;

  directNoPrefix             = directMeta "noPrefix"        null; # Don't apply any prefix
  directPrefix               = directMeta "prefix"          null; # Apply inferred prefix (after `toLower`)
  directPrefixNoLower        = directMeta "prefixNoLower"   null;
  directPrefixAlias   = alias: directMeta "prefixAlias"     alias;

  directSection              = directMeta "section"         null;
  directSectionNoLower       = directMeta "sectionNoLower"  null;
  directSectionAlias  = alias: directMeta "sectionAlias"    alias;

  directSpecial              = directMeta "special"         null; # Option require manual mapping
  directIgnore               = directMeta "ignore"          null; # Option is not in i2pd config

  # Module parser panics if it can't find any option in attrset
  removeMeta = filterAttrsRecursive (k: _: k != metaAttrName);

  /* Print line in i2pd config convention
  * Note:
  *     Returns `null` if `value` is `null` or `[]`
  *
  * Example:
  *   printLine "option_name" "valid_value"
  *   => "option_name = valid_value"
  *   printLine "option_name" null
  *   => null
  */
  printLine = alias: value:
    let
      printValue = value:
        if      isString  value then value
        else if isBool    value then boolToString value
        else if isInt     value then toString value
        else if isList    value then concatStringsSep "," (map printValue value)
        else throw "This case should never happen";
    in
    if value == null || value == [] then null # "${alias} = debug_value" # Print all hidden options
    else "${alias} = ${printValue value}";

  # Simular to types.enum of `attrNames attrset` but maps merged result to `attrset.${value}`
  attrEnum = attrset:
    types.enum (attrNames attrset) // {
      merge = loc: defs: attrset.${mergeEqualOption loc defs};
      functor = types.enum.functor // { type = attrEnum; payload = attrset; binOp = a: b: a // b; };
    };

  # Simular to `lists.getAttrs` but allows access nested attributes
  # Example:
  #     getAttrsRecursive [ "a.b" "d" ] { a = { b = 1; c = 2; }; d = 3; }
  #     => { a = { b = 1; }; d = 3; }
  getAttrsRecursive = names: attrset:
    let
      recurse = paths: attrset:
        mapAttrs (k: v:
          let next = map (drop 1) v; in
            if any (e: e == []) next
              then attrset.${k}
              else recurse next attrset.${k})
          (groupBy (path: head path) paths);
    in
    recurse (forEach names (splitString ".")) attrset;

  ## Generic options ##
  requiredOptionOfType = type: description:
    mkOption { inherit type; description = lib.mdDoc description; };
  requiredPort    = requiredOptionOfType types.port;
  requiredString  = requiredOptionOfType types.str;

  # Default value is specified by caller
  defaultOptionOfType = type: default: description: requiredOptionOfType type description // { inherit default; };
  defaultBool               = defaultOptionOfType types.bool;
  defaultUint               = defaultOptionOfType types.ints.unsigned;
  defaultInt                = defaultOptionOfType types.int;
  defaultPort               = defaultOptionOfType types.port;
  defaultString             = defaultOptionOfType types.str;
  defaultListOf       = type: defaultOptionOfType (types.listOf type);
  defaultAttrsetOf    = type: defaultOptionOfType (types.attrsOf type);
  defaultEnum     = variants: defaultOptionOfType (types.enum variants);
  defaultAttrEnum  = attrset: defaultOptionOfType (attrEnum attrset);
  defaultEnable = default: name: mkEnableOption (lib.mdDoc name) // { inherit default; };

  # Default value is null
  nullOptionOfType = type: defaultOptionOfType (types.nullOr type) null;
  nullBool                = nullOptionOfType types.bool;
  nullUint                = nullOptionOfType types.ints.unsigned;
  nullInt                 = nullOptionOfType types.int;
  nullPort                = nullOptionOfType types.port;
  nullString              = nullOptionOfType types.str;
  nullAttrEnum   = attrset: nullOptionOfType (attrEnum attrset);

  ###### Interface #####

  optionsWithMeta.services.i2pd = {
    enable = defaultBool false ''
      Enables I2Pd as a running service upon activation.
      Please read http://i2pd.readthedocs.io/en/latest/ for further
      configuration help.'' // directIgnore;

    package = mkOption {
      type = types.package;
      default = pkgs.i2pd;
      defaultText = literalExpression "pkgs.i2pd";
      description = lib.mdDoc "i2pd package to use";
    } // directIgnore;

    dataDir = defaultString
      "/var/lib/i2pd"
      "Path to storage of i2pd data (RouterInfos, destinations keys, peer profiles, etc ...)" // directIgnore;

    gracefulShutdown = defaultBool false ''
      If true, i2pd will be wait for closing transit connections.
      Enabling this option **may delay system shutdown/reboot/rebuild-switch up to 10 minutes!**
    '' // directIgnore;

    autoRestart = defaultBool true ''
      If true, i2pd will be restarted on failure (does not affect clean exit).
    '' // directIgnore;

    # General
    logLevel = defaultEnum
      ["debug" "info" "warn" "error"]
      "error"
      ''The log level. {command}`i2pd` defaults to "info"
        but that generates copious amounts of log messages.

        We default to "error" which is similar to the default log
        level of {command}`tor`.'' // direct;
    logCLFTime = defaultEnable false "Full CLF-formatted date and time to log" // direct;

    port = nullPort "I2Pd common listen port (`null` = router will pick between 9111 and 30777)" // direct;

    ifname = nullString "Network interface to bind to" // direct;
    ifname4 = nullString "Network interface to bind to for IPv4" // direct;
    ifname6 = nullString "Network interface to bind to for IPv6" // direct;
    address = nullString "Router external IP for incoming connections" // directIgnore;
    address4 = nullString "Local address to bind to for IPv4" // direct;
    address6 = nullString "Local address to bind to for clearnet IPv6" // direct;

    nat = defaultEnable true "NAT bypass" // direct;
    enableIPv4 = defaultEnable true "IPv4 connectivity" // directAlias "ipv4";
    enableIPv6 = defaultEnable false "IPv6 connectivity" // directAlias "ipv6";

    allowTransit = defaultBool true ''
      If `true` router will be accepting transit tunnels.
      If `false` transit traffic will be disabled completely.'' // directSpecial;

    floodfill = defaultBool false "Router will be floodfill" // direct;

    bandwidth = nullOptionOfType
      (types.either types.int (attrEnum { "32KBps" = "L"; "256KBps" = "O"; "2048KBps" = "P"; "UNLIMITED" = "X";}))
      ''Set a router bandwidth limit: integer in KBps or word.
        Note that integer bandwith will be rounded.
        If not set, {command}`i2pd` defaults to 32KBps.'' // direct;
    share = nullOptionOfType (types.ints.between 0 100) "Limit of transit traffic from max bandwidth in percents" // direct;

    family = nullString "Specify a family the router belongs to" // direct;
    netid = nullUint "I2P overlay netid" // direct;

    # UPNP
    upnp = directSection // {
      enable = defaultEnable false "UPnP service discovery" // directAlias "enabled";
      name = nullString "Name i2pd appears in UPnP forwardings list" // direct;
    };

    # Cryptography
    precomputation = directSection // {
      elgamal = defaultBool true ''
        Whenever to use precomputated tables for ElGamal.
        {command}`i2pd` defaults to `false`
        to save 64M of memory (and looses some performance).

        We default to `true` as that is what most
        users want anyway.''
        // direct;
    };

    # Reseeding
    reseed = directSection // {
      verify = defaultEnable false "SU3 signature verification" // direct;
      # I2pd router has defaults itself
      urls = defaultListOf types.str [] "Reseed URLs" // direct;
      yggurls = defaultListOf types.str [] "Reseed Yggdrasil's URLs" // direct;
      file = nullString "Path to local .su3 file or HTTPS URL to reseed from" // direct;
      zipfile = nullString "Path to local .zip file to reseed from" // direct;
      threshold = nullUint "Minimum number of known routers before requesting reseed" // direct;
      floodfill = nullString "Path to router info of floodfill to reseed from" // direct;
      proxy = nullString "Url for https/socks reseed proxy" // direct;
    };

    # Addressbook
    addressbook = directSection // {
      # I2pd router has defaults itself
      defaulturl = nullString "AddressBook subscription URL for initial setup" // direct;
      subscriptions = defaultListOf types.str [] "AddressBook subscription URLs" // direct;
      hostsFile = nullString "File to dump AddressesBook in hosts.txt format" // direct;
    };

    # NTCP2
    ntcp2 = directSection // {
      enable = defaultEnable true "NTCP2" // directAlias "enabled";
      published = defaultBool true "Enable incoming NTCP2 connections" // direct;
      port = nullPort "Port to listen for incoming NTCP2 connections (`null`: common port)" // direct;
      proxy = nullString "Specify proxy server for NTCP2. Should be `http://address:port` or `socks://address:port`" // direct;
    };

    # SSU2
    ssu2 = directSection // {
      enable = defaultEnable true "SSU2" // directAlias "enabled";
      published = defaultBool true "Enable incoming SSU2 connections" // direct;
      port = nullPort "Port to listen for incoming SSU2 connections (`null`: common port)" // direct;
      proxy = nullString "Specify UDP socks5 proxy server for SSU2. Should be `socks://address:port`" // direct;
      mtu4 = nullUint "MTU for local ipv4" // direct;
      mtu6 = nullUint "MTU for local ipv6" // direct;
    };

    # Limits
    limits = directSection // {
      transittunnels = nullUint "Maximum number of active transit tunnels" // direct;
      coreSize = nullUint "Maximum size of corefile in Kb (`null`: use system limit)" // direct;
      openFiles = nullUint "Maximum size of open files (`null`: use system limit)" // direct;
    };

    # Trust
    trust = directSection // {
      enable = defaultEnable true "Explicit trust options" // directAlias "enabled";
      family = nullString "Router Family to trust for first hops" // direct;
      routers = defaultListOf types.str [] "Only connect to the listed routers" // direct;
      hidden = defaultEnable false "Router concealment" // direct;
    };

    # Exploratory
    exploratory = directSection // rec {
      inbound = {
        length = defaultUint 2 "Exploratory tunnels length" // direct;
        quantity = defaultUint 3 "Exploratory tunnels quantity" // direct;
      } // directPrefix;
      outbound = inbound;
    };

    # Time sync
    timeSync = directSectionAlias "nettime" // {
      enable = defaultEnable false "NTP sync" // directAlias "enabled";
      servers = defaultListOf types.str ["pool.ntp.org"] "List of NTP servers" // directAlias "ntpservers";
      interval = defaultUint 72 "NTP time sync interval in hours" // directAlias "ntpsyncinterval";
    };

    # Network information persist
    persist = directSection // {
      peerProfiles = defaultEnable true "Peer profile persisting to disk" // directAlias "profiles";
      addressbook = defaultEnable true "Save full addresses on disk" // direct;
    };

    # Meshnets transports
    yggdrasil = directSectionAlias "meshnets" // {
      enable = defaultEnable false "Yggdrasil" // directAlias "yggdrasil";
      address = nullString "Your local yggdrasil address. Specify it if you want to bind your router to a particular address" // directAlias "yggaddress";
    };

    # UNIX-specific
    handleSigStop = defaultBool false ''
      When signal recveived, i2pd will switch to offline mode and stop sending traffic and cleaning of netDb. All active tunnels will be frozen.
      Enable offline mode: `systemctl kill --signal SIGSTOP i2pd`
      Disable offline mode: `systemctl kill --signal SIGCONT i2pd`
    '' // directSpecial;

    proto = directNoPrefix //
      (let
        genericEndpoint = description: port: {
          enable = defaultEnable false description // directAlias "enabled";
          address = templates.bindAddress // direct;
          port = defaultPort port "The port to listen on" // direct;
        };
        genericInterface = name: genericEndpoint "${name} interface";
        genericProxy = name: port:
          genericEndpoint "${name} proxy" port // {
          keys = nullOptionOfType (types.strMatching ".*-keys\.dat") ''
            Keys for local destination.
            If keys is `null`, transient keys will be created on every restart.
          '' // direct;
          signatureType = templates.signatureType // direct;
        } // flip getAttrsRecursive templates.i2cpParametersOptions
          [ "inbound" "outbound" "i2cp.${metaAttrName}" "i2cp.leaseSetType" "i2cp.leaseSetEncType" ];
      in {
        # WebUi
        http = attrsets.recursiveUpdate (genericEndpoint "HTTP webconsole" 7070) {
          enable.default = true;
          auth = defaultEnable false "Enable basic HTTP auth for webconsole" // direct;
          user = nullString "Username for basic auth (`null` = \"i2pd\")" // direct;
          pass = nullString "Password for basic auth (`null` = random, see logs)" // direct;
          strictHeaders = defaultEnable true "Strict host checking" // direct;
          hostname = nullString "Expected hostname (`null` = localhost)" // direct;
        } // directSection;
        # Proxy
        httpProxy = attrsets.recursiveUpdate (genericProxy "HTTP" 4444) {
          enable.default = true;
          addressHelper = defaultEnable true "Address helper (jump)" // direct;
          outproxy = nullString "HTTP outproxy URL (requests outside I2P will go there)" // direct;
        } // directSection;
        socksProxy = attrsets.recursiveUpdate (genericProxy "SOCKS5" 4447) {
          enable.default = true;
          outproxyEnable = defaultEnable false "SOCKS outproxy (requests outside I2P will go there)" // directAlias "outproxy.enabled";
          outproxy = defaultString "127.0.0.1" "Upstream outproxy address for SOCKS Proxy" // direct;
          outproxyPort = defaultPort 9050 "Upstream outproxy port for SOCKS Proxy" // direct;
        } // directSection;
        # Interface
        sam = genericInterface "sam" 7656 // {
          singleThread = defaultEnable true "Run every I2CP session runs in own thread" // direct;
        } // directSection;
        bob = genericInterface "bob" 2827 // directSection;
        i2cp = genericInterface "i2cp" 7654 // {
          singleThread = defaultEnable true "Run every I2CP session runs in own thread" // direct;
        } // directSection;
        i2pControl = genericInterface "i2pcontrol" 7650 // {
          password = nullString "I2P control authentication password" // direct;
          cert = nullString "I2P control HTTPS certificate file name" // direct;
          key = nullString "I2P control HTTPS certificate key file name" // direct;
        } // directSection;
      });

    outTunnels = defaultAttrsetOf
      (types.submodule ({ name, ... }: (removeMeta (templates.outTunnels name)))) {}
      "Connect to someone as a client and establish a local accept endpoint" // directIgnore;

    inTunnels = defaultAttrsetOf
      (types.submodule ({ name, ... }: (removeMeta (templates.inTunnels name)))) {}
      "Serve something on I2P network and delegate requests to `address:port`" // directIgnore;
  };
  templates = {
    # Client tunnels
    # https://i2pd.readthedocs.io/en/latest/user-guide/tunnels/#client-tunnels
    outTunnels = name: {
      options = directSectionNoLower // templates.i2cpParametersOptions // {
          enable = defaultEnable true "${name}" // directIgnore;
          type = defaultEnum [ "client" ] "client" "I2P tunnel type" // { visible = false; } // direct;
          destination = requiredString "Remote endpoint, I2P hostname or b32.i2p address" // direct;
          port = requiredPort "Port of client tunnel (on this port i2pd will receive data)" // direct;
          address = templates.bindAddress // direct;
          keepaliveInterval = nullUint "Send ping to the destination after this interval in seconds" // direct;
          signatureType = templates.signatureType // direct;
          keys = nullOptionOfType (types.strMatching ".*-keys\.dat") ''
            Keys for destination. When same for several tunnels, will be using same destination for every tunnel.
            If keys is `null`, transient keys will be created on every restart.'' // direct;

          # DEPRECATED: Option had misleading description.
          # Because "destination port" is being selected at server-side only and can't be changed by other node.
          # AFAIK "destination port" is used to select tunnel in received LeaseSet (quiet useless, do anybody ever used it?).
          # I didn't figure out how to deprecate option in submodule, so just left it here:
          # Message: "Option `config.services.i2pd.outTunnels.<name>.destinationPort` is deprecated. Use `port` instead"
          destinationPort = mkOption { visible = false; } // directIgnore;
        };
      };
    # Server/generic tunnels
    # https://i2pd.readthedocs.io/en/latest/user-guide/tunnels/#servergeveric-tunnels
    inTunnels = name: {
      options = directSectionNoLower // templates.i2cpParametersOptions // {
          enable = defaultEnable true "${name}" // directIgnore;
          type = defaultEnum [ "server" ] "server" "I2P tunnel type" // { visible = false; } // direct;
          address = requiredString "IP address of server (on this address i2pd will send data from I2P)" // directAlias "host";
          port = requiredPort "Port of server tunnel (on this port i2pd will send data from I2P)" // direct;
          accessList = defaultListOf types.str []
            "List of of b32 address (without .b32.i2p) allowed to connect. Everybody is allowed by default" // direct;
          compression = defaultEnable false "Internal compression (gzip)" // directAlias "gzip";
          signatureType = templates.signatureType // direct;
          keys = defaultOptionOfType (types.strMatching ".*-keys\.dat") (name + "-keys.dat") ''
            Keys for destination. When same for several tunnels, will be using same destination for every tunnel.
            If keys is `""`, transient keys will be created on every restart.'' // direct;

          # DEPRECATED: Option had misleading description.
          # It seems "inPort" is owerwrites "port" or something, but i didn't get it.
          # I didn't figure out how to deprecate option in submodule, so just left it here
          # Message: "Option `config.services.i2pd.inTunnels.<name>.inPort` is deprecated. Use `port` instead"
          inPort = mkOption { visible = false; } // directIgnore;
        };
      };

    # Common for all tunnels except exploratory
    # https://i2pd.readthedocs.io/en/latest/user-guide/tunnels/#i2cp-parameters
    i2cpParametersOptions = rec {
      # It seems i2cp parameters have camelCase convention here...
      outbound = inbound;
      inbound = directPrefixNoLower // {
        length = nullUint "Number of hops in each tunnel" // directNoLower;
        quantity = nullUint "Number of tunnels" // directNoLower;
        lengthVariance = nullInt "Random number of hops to add or subtract" // directNoLower;
      };
      crypto = directPrefixNoLower // {
        tagsToSend = nullUint "Number of ElGamal/AES tags to send" // directNoLower;
      };
      explicitPeers = defaultListOf types.str [] "List of b64 addresses of peers to use" // directNoLower;
      i2p = directPrefixNoLower // {
        streaming = directPrefixNoLower // {
          initialAckDelay = nullUint "Milliseconds to wait before sending Ack" // directNoLower;
          answerPings = nullBool "Enable sending pongs" // directNoLower;
        };
      };
      i2cp = directPrefixNoLower // {
        leaseSetType = nullAttrEnum
          { "standard" = 3;
            "encrypted" = 5; }
          "Type of LeaseSet to be sent" // directNoLower;
        leaseSetEncType = defaultListOf
          (attrEnum {
            "ELGAMAL" = 0;
            "ECIES_P256_SHA256_AES256CBC" = 1;
            "ECIES_X25519_AEAD" = 4;
          }) []
          "List of LeaseSet encryption types" // directNoLower;
        leaseSetPrivKey = nullString "Decryption key for encrypted LeaseSet in base64. PSK or private DH" // directNoLower;
        leaseSetAuthType = nullAttrEnum
          { "none" = 0;
            "DH" = 1;
            "PSK" = 2; }
          "Authentication type for encrypted LeaseSet" // directNoLower;
        leaseSetClient = directPrefixNoLower // {
          dh = defaultAttrsetOf types.str {} "Client's public DHs in base64, for authentication type DH" // directSpecial
            // { example =
            ''
              {
                "Bob" = "Bob's public DH key in base64";
                "Alice" = "Alice's public DH key in base64";
              }
            ''; };
          psk = defaultAttrsetOf types.str {} "Client's PSKs in base64, for authentication type PSK" // directSpecial
            // { example =
            ''
              {
                "Bob" = "Bob's password in base64";
                "Alice" = "Alice's password in base64";
              }
            ''; };
        };
      };
    };
    # This option is part of both client and server tunnels but not documented as i2cp parameter
    signatureType = nullAttrEnum
        { "ECDSA-P256" = 1;
          "ECDSA-P384" = 2;
          "ECDSA-P521" = 3;
          "ED25519-SHA512" = 7;
          "GOSTR3410-A-GOSTR3411-256" = 9;
          "GOSTR3410-TC26-A-GOSTR3411-512" = 10;
          "RED25519-SHA512" = 11; }
        ''Signature type for new keys.
          `ED25519-SHA512` is default.
          `RED25519-SHA512` is recommended for encrypted leaseset.'';
    bindAddress = defaultEnum [ "127.0.0.1" "0.0.0.0" "::" "fe80::" ] "127.0.0.1" ''
      Local interface address listen socket binds to.
      `"127.0.0.1"` for connections from local host only.
      `"0.0.0.0"` for connections from everywhere.'';
  };
in
{
  imports =
    let
      deprecate = msg: map (option: mkRemovedOptionModule (splitString "." ("services.i2pd.${option}")) msg);
    in deprecate "This option has been deprecated upstream" [
    # https://github.com/PurpleI2P/i2pd/blob/71bad23906f47113b8cfb9f906e0d76cc8d6c3b5/libi2pd/Config.cpp#L66-68
    "ntcpProxy" "ntcp" "ssu"
    # https://github.com/PurpleI2P/i2pd/blob/71bad23906f47113b8cfb9f906e0d76cc8d6c3b5/libi2pd/Config.cpp#L256-258
    "websockets"
    # https://github.com/PurpleI2P/i2pd/blob/71bad23906f47113b8cfb9f906e0d76cc8d6c3b5/libi2pd/Config.cpp#L81-L83
    "limits.ntcpHard" "limits.ntcpSoft" "limits.ntcpThreads" ]
    ++ deprecate "Use `allowTransit` instead" [ "notransit" ];
    # Option `options.i2pd.outTunnels.<name>.destinationPort` is also silently deprecated.
    # Option `options.i2pd.inTunnels.<name>.inPort` is also silently deprecated.

  options.services.i2pd = removeMeta optionsWithMeta.services.i2pd;

  ###### Implementation ######

  config =
    let
      cfg = config.services.i2pd;

      notice = "# DO NOT EDIT -- this file has been generated automatically.";

      # Format: `i2cp.leaseSetClient.(dh/psk).(unique integer) = (client's name):(key in base64)`
      printTunnelI2cpLeaseSetClientKeys = prefix: keys:
        flip genList (length (attrNames keys))
          (n: "${prefix}.${toString n} = ${elemAt (attrNames keys) n}:${elemAt (attrValues keys) n}");

      # Parse declared options directly to configuration files
      i2pdFlags = cfg: opts:
        let
          writeFile = filename: lines: pkgs.writeText filename (concatStringsSep "\n" ([ notice ] ++ lines) + "\n");
          i2pdConf = writeFile "i2pd.conf" (configGenerator cfg opts);
          tunConf = writeFile "i2pd-tunnels.conf"
            (let parse = type:
              flip concatMap
                (attrNames cfg.${type})
                (name: configGenerator
                    { ${name} = cfg.${type}.${name}; }
                    { ${name} = (templates.${type} name).options; });
              in parse "inTunnels" ++ parse "outTunnels");
          # See `Configuration Generator` for basic functionality description
          # Note: `pkgs.format.ini` does not allow "prefixing" attributes and laks aliasing
          configGenerator = cfg: opts:
            let
              sortedConfig =
                  # Ensure that all general options are printed before any section
                  # General options are `[ true "line" ]`
                  # Other options are `[ false "line"]` or `"line"`
                  concatLists
                    (mapAttrsFlatten
                      (_: map (v: if isList v then last v else v))
                      (groupBy
                        (e: if isList e && head e then "0_general" else "1_other")
                        (scan cfg opts "" true)));
              scan = cfg: opts: prefix: isTopLevel:
                  (concatLists
                    (forEach (attrNames cfg)
                      (option:
                        let
                          cfg' = cfg.${option};
                          opts' = opts.${option};
                          has = name: hasAttrByPath [ option metaAttrName name ] opts;
                          get = name: getAttrFromPath [ option metaAttrName name ] opts;
                        in
                        if has "ignore" || option == metaAttrName || ! opts ? ${option}
                          then []
                        else if has "option" # Attribute name is configuration alias
                          then [ [ isTopLevel (printLine (prefix + toLower option) cfg') ] ]

                        else if has "optionNoLower" # Attribute name is configuration alias
                          then [ [ isTopLevel (printLine (prefix + option) cfg') ] ]

                        else if has "optionAlias" # Configuration alias is specified
                          then [ [ isTopLevel (printLine (prefix + get "optionAlias") cfg') ] ]

                        else if has "section" && prefix == "" # Prefix can't be applied to sections
                          then [ "\n[${toLower option}]" ] ++ (scan cfg' opts' prefix false)

                        else if has "sectionNoLower" && prefix == "" # Prefix can't be applied to sections
                          then [ "\n[${option}]" ] ++ (scan cfg' opts' prefix false)

                        else if has "sectionAlias" && prefix == "" # Prefix can't be applied to sections
                          then [ "\n[${get "sectionAlias"}]" ] ++ (scan cfg' opts' prefix false)

                        else if has "noPrefix"
                          then scan cfg' opts' prefix false

                        else if has "prefix"
                          then scan cfg' opts' (prefix + (toLower option) + ".") false

                        else if has "prefixNoLower"
                          then scan cfg' opts' (prefix + option + ".") false

                        else if has "prefixAlias"
                          then scan cfg' opts' (prefix + get "prefixAlias" + ".") false

                        else if has "special"
                          then {
                            "handleSigStop" = [ "\n[unix]" (printLine "handle_sigtstp" cfg')];
                            "allowTransit" = [ [ isTopLevel (printLine "notransit" (! cfg')) ] ];
                            "i2cp.leaseSetClient.dh" = printTunnelI2cpLeaseSetClientKeys (prefix + option) cfg';
                            "i2cp.leaseSetClient.psk" = printTunnelI2cpLeaseSetClientKeys (prefix + option) cfg';
                          }.${prefix + option}

                        else throw "Error in option definition: `optionsWithMeta.services.i2pd.**.${prefix + option}` lacks parsing metadata" [])));
            in
              lists.remove null sortedConfig;
        in
        concatStringsSep " "
          (remove null [
            (if isString cfg.address then "--host=" + cfg.address else null)
            ("--conf=" + i2pdConf)
            ("--tunconf=" + tunConf)]);
    in
    mkIf cfg.enable {

      users.users.i2pd = {
        group = "i2pd";
        description = "I2Pd User";
        home = cfg.dataDir;
        createHome = true;
        uid = config.ids.uids.i2pd;
      };

      users.groups.i2pd.gid = config.ids.gids.i2pd;

      systemd.services.i2pd = {
        description = "Minimal I2P router";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          User = "i2pd";
          WorkingDirectory = cfg.dataDir;
          ExecStart = "${cfg.package}/bin/i2pd ${i2pdFlags cfg optionsWithMeta.services.i2pd}";
          ## Auto restart
          Restart = if cfg.autoRestart then "on-failure" else "no";
          ## Graceful shutdown
          KillSignal = if cfg.gracefulShutdown then "SIGINT" else "SIGTERM";
          TimeoutStopSec = if cfg.gracefulShutdown then "10m" else "30s";
          SendSIGKILL = true;
          ## Hardening
          # Taken from https://github.com/archlinux/svntogit-community/blob/packages/i2pd/trunk/030-i2pd-systemd-service-hardening.patch
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectControlGroups = true;
          NoNewPrivileges = true;
          MemoryDenyWriteExecute = true;
          LockPersonality = true;
          SystemCallFilter = "@system-service";
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6 AF_NETLINK";
          ProtectHostname = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          PrivateMounts = true;
          PrivateUsers = true;
          ReadWritePaths = cfg.dataDir;
          RemoveIPC = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
        };
      };
    };
}

