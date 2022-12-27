/******
 * This helper class is designed to simplify init of Web3 Wallet connections
 * for vanilla JS implementations.
 *
 * The problem being solved is that every wallet has a slightly different init
 * process, and slightly different mechanism to determine if the wallet is
 * present in the user's browser.
 *
 * The solution provides for a standardised way to query for wallet presence,
 * and connection init, returning an initialised Web3.js wallet object.
 *
 * Currently supports WalletConnect, MetaMask, Binance Wallet, Coinbase Wallet
 * or simply reading chain information via Infura.
 *
 * Depends on Web3.js and WalletConnect JS files - however these are
 * imported through the init function.
 *
 * Copyright (c) 2022 Kaiesh Vohra
 * License: GPL
 *******/
var ajax=ajax||function(a,b){var d="",c;for(c in a)a.hasOwnProperty(c)&&(d+=(""==d?"":"&")+c+"="+encodeURIComponent(a[c]));var e={api_url:"/api/",request_header:"application/x-www-form-urlencoded",json_return:!0,method:"POST"};if("object"==typeof b)for(c in b)b.hasOwnProperty(c)&&(e[c]=b[c]);return new Promise(function(f,h){var g=new XMLHttpRequest;g.open(e.method,e.api_url);g.setRequestHeader("Content-Type",e.request_header);g.onload=function(){if(200===g.status){var k=e.json_return?JSON.parse(g.responseText):
g.responseText;f(k)}else h({status:"fail",resp:k})};g.send(d)})},shield=shield||function(a,b,d,c,e,f){c=document.createElement(c);c.src=a;"function"==typeof b&&(c.onload=b);c.async="async";document.getElementsByTagName(d)[e].appendChild(c)},showToast=showToast||function(a,b){var d=Math.floor(1E3*Math.random()),c=document.createElement("DIV");c.id="toast"+d;c.innerHTML=a;c.className="toast "+b;document.getElementsByTagName("body")[0].appendChild(c);setTimeout(function(){c.parentElement.removeChild(c)},
5E3)},KV=KV||{_infuraID:null,_provider_name:localStorage.getItem("provider_name")?localStorage.getItem("provider_name"):"readonly",rpc_url:{1:null,3:null,42:null,56:"https://bsc-dataseed.binance.org/",97:"https://data-seed-prebsc-1-s1.binance.org:8545/"},rpc_codes:{ETH_MAINNET:1,ETH_ROPSTEN:3,ETH_KOVAN:42,BSC_MAINNET:56,BSC_TESTNET:97},network_humannames:{1:"Ethereum Mainnet",3:"Ethereum Ropsten",42:"Ethereum Kovan",56:"Binance Smart Chain",97:"Binance Smart Chain Test"}};
KV.init=function(a){return KV._init_complete?new Promise(function(b){b()}):new Promise(function(b,d){try{var c=0,e=["https://cdn.kaiesh.com/js/web3_3.0.0-rc.5.min.js","https://cdn.kaiesh.com/js/walletconnect_1.7.1.min.js"],f=Array.isArray(a)?e.concat(a):e;e=function(){c++;c>=f.length&&(KV._init_complete=!0,localStorage.getItem("chainId")&&localStorage.getItem("provider")?(KV._provider_name=localStorage.getItem("provider"),KV.wallet.enable(localStorage.getItem("chainId")).then(function(g){b({init:"ok",
wallet:"ok"})})["catch"](function(g){b({init:"ok",wallet:"fail"})})):b({init:"ok"}))};for(var h=0;h<f.length;h++)shield(f[h],e,"head","script",0)}catch(g){d(g)}})};KV.set_infuraID=function(a){KV._infuraID=a;KV.rpc_url[1]="https://mainnet.infura.io/v3/"+a;KV.rpc_url[3]="https://ropsten.infura.io/v3/"+a;KV.rpc_url[42]="https://kovan.infura.io/v3/"+a};
KV.get_available_providers=function(){var a=[];a.push("walletconnect");"object"==typeof window.ethereum&&window.ethereum.isMetaMask&&a.push("metamask");"object"==typeof window.BinanceChain&&a.push("binancewallet");return a};KV.set_provider=function(a){switch(a){case "metamask":case "walletconnect":case "binancewallet":case "readonly":KV._provider_name=a;localStorage.setItem("provider_name",a);break;default:throw Exception("Invalid provider specified");}};KV.get_provider=function(){return KV._provider_name};
KV.wallet={reset_all:function(){KV.wallet._hooks.disconnect=[];KV.wallet._hooks.connect=[];KV.wallet._hooks.session_change=[];localStorage.removeItem("chainId");localStorage.removeItem("provider");KV.wallet.walletconnect._provider=null;KV.wallet.walletconnect._web3=null;KV.wallet.metamask._provider=null;KV.wallet.metamask._web3=null;KV.wallet.binancewallet._provider=null;KV.wallet.binancewallet._web3=null;KV.wallet.coinbasewallet._provider=null;KV.wallet.coinbasewallet._web3=null;KV.wallet.readonly._provider=
null;KV.wallet.readonly._web3=null;KV._provider_name=null},on_disconnect:function(a){"function"==typeof a&&KV.wallet._hooks.disconnect.push(a)},on_session_change:function(a){"function"==typeof a&&KV.wallet._hooks.session_change.push(a)},on_connect:function(a){"function"==typeof a&&KV.wallet._hooks.connect.push(a)},_process_session_update:function(a){for(var b=0;b<KV.wallet._hooks.session_change.length;b++)"function"==typeof KV.wallet._hooks.session_change[b]?function(d){setTimeout(function(){d(a)},
10)}(KV.wallet._hooks.session_change[b]):console.error("Session change hooks",KV.wallet._hooks.session_change[b],"This is not a function")},_process_disconnection:function(a){for(var b=0;b<KV.wallet._hooks.disconnect.length;b++)"function"==typeof KV.wallet._hooks.disconnect[b]?function(d){setTimeout(function(){d(a)},10)}(KV.wallet._hooks.disconnect[b]):console.error("Disconnection hooks",KV.wallet._hooks.disconnect[b],"This is not a function");KV.wallet.reset_all()},_process_connect:function(a){for(var b=
0;b<KV.wallet._hooks.connect.length;b++)"function"==typeof KV.wallet._hooks.connect[b]?function(d){setTimeout(function(){d(a)},10)}(KV.wallet._hooks.connect[b]):console.error("Disconnection hooks",KV.wallet._hooks.connect[b],"This is not a function")},_hooks:{disconnect:[],session_change:[],connect:[]},walletconnect:{enable:function(a){return new Promise(function(b,d){null==KV.rpc_url[a]?d({code:-1,debug:"Invalid RPC url for this network. You might need an Infura ID for Wallet Connect to work on this network.\n\nUse the function KV.set_infuraID(str) to set your Infura ID before invoking this method."}):
(KV.wallet.walletconnect._provider=new WalletConnectProvider["default"]({infuraId:KV._infuraID,rpc:KV.rpc_url,chainId:a}),KV.wallet.walletconnect._provider.chainId=a,KV.wallet.walletconnect._provider.enable().then(function(c){KV.wallet.walletconnect._web3=new Web3(KV.wallet.walletconnect._provider);localStorage.setItem("chainId",a);KV.wallet.walletconnect._provider.on("disconnect",KV.wallet._process_disconnection);KV.wallet.walletconnect._provider.on("session_update",KV.wallet._process_session_update);
KV.wallet._process_connect(c);b(c)})["catch"](function(c){d(c)}))})}},binancewallet:{enable:function(a){return new Promise(function(b,d){"object"!=typeof window.BinanceChain&&d({code:-1,debug:"Binance Chain wallet not found. Please query available providers before invoking."});KV.wallet.binancewallet._provider=window.BinanceChain;1==a&&"0x01"!=window.BinanceChain.chainId&&window.BinanceChain.chainId!="0x"+Number(a).toString(16)?d({code:4901,target_network:"0x"+Number(a).toString(16),actual_network:window.BinanceChain.chainId}):
KV.wallet.binancewallet._provider.enable().then(function(c){KV.wallet.binancewallet._web3=new Web3(window.BinanceChain);localStorage.setItem("chainId",a);KV.wallet.binancewallet._provider.on("disconnect",KV.wallet._process_disconnection);KV.wallet.binancewallet._provider.on("accountsChanged",KV.wallet._process_session_update);KV.wallet._process_connect(c);b(c)})["catch"](function(c){d(c)})})}},coinbasewallet:{enable:function(a){return new Promise(function(b,d){if("object"==typeof window.ethereum&&
Array.isArray(window.ethereum.providers)){for(var c=0;c<window.ethereum.providers.length;c++)if(window.ethereum.providers[c].isCoinbaseWallet){KV.wallet.coinbasewallet._provider=window.ethereum.providers[c];break}KV.wallet.coinbasewallet._provider.request({method:"wallet_switchEthereumChain",params:[{chainId:"0x"+Number(a).toString(16)}]}).then(function(e){console.log(e);KV.wallet.coinbasewallet._provider.enable().then(function(f){console.log(f);KV.wallet.coinbasewallet._web3=new Web3(KV.wallet.coinbasewallet._provider);
localStorage.setItem("chainId",a);KV.wallet.coinbasewallet._provider.on("disconnect",KV.wallet._process_disconnection);KV.wallet.coinbasewallet._provider.on("accountsChanged",KV.wallet._process_session_update);KV.wallet._process_connect(f);b(f)})["catch"](function(f){d(f)})})["catch"](function(e){d(e)})}else d({code:-1,debug:"Wallet provider not available"})})}},metamask:{enable:function(a){return new Promise(function(b,d){if(window.ethereum){if(Array.isArray(window.ethereum.providers))for(var c=
0;c<window.ethereum.providers.length;c++){if(window.ethereum.providers[c].isMetaMask){var e=window.ethereum.providers[c];break}}else e=window.ethereum;KV.wallet.metamask._provider=e;KV.wallet.metamask._provider.request({method:"wallet_switchEthereumChain",params:[{chainId:"0x"+Number(a).toString(16)}]}).then(function(f){KV.wallet.metamask._provider.enable().then(function(h){KV.wallet.metamask._web3=new Web3(window.ethereum);localStorage.setItem("chainId",a);KV.wallet.metamask._provider.on("disconnect",
KV.wallet._process_disconnection);KV.wallet.metamask._provider.on("accountsChanged",KV.wallet._process_session_update);KV.wallet._process_connect(h);b(h)})["catch"](function(h){d(h)})})["catch"](function(f){d(f)})}else window.web3?(KV.wallet.metamask._web3=window.web3,localStorage.setItem("chainId",a),KV.wallet._process_connect(),b()):(KV.wallet.metamask._provider=new Web3.providers.HttpProvider("http://127.0.0.1:9545"),KV.wallet.metamask._provider.chainId=a,KV.wallet.metamask._web3=new Web3(KV.wallet.metamask._provider),
localStorage.setItem("chainId",a),KV.wallet.metamask._provider.on("disconnect",KV.wallet._process_disconnection),KV.wallet.metamask._provider.on("accountsChanged",KV.wallet._process_session_update),d())})}},readonly:{enable:function(a){return new Promise(function(b,d){KV.wallet.readonly._provider=new Web3.providers.HttpProvider(KV.rpc_url[a]);KV.wallet.readonly._web3=new Web3(KV.wallet.readonly._provider);KV.wallet._process_connect();localStorage.setItem("chainId",a);b()})}}};
KV.wallet.enable=function(a){a||(a=KV.rpc_codes.ETH_MAINNET);return KV.wallet[KV._provider_name].enable(a)};KV.wallet.web3=function(){return KV.wallet[KV._provider_name]._web3};KV.wallet.disconnect=function(){"walletconnect"==KV._provider_name&&KV.wallet.walletconnect._provider.disconnect().then(console.log)["catch"](console.log);KV.wallet.reset_all()};KV.Contract=function(a){this.contract_address=a};
KV.Contract.prototype.load=function(a){var b=this;return new Promise(function(d,c){ajax([],{api_url:"string"==typeof a?a:"/rpc-data/"+b.contract_address+".json",method:"GET"}).then(function(e){var f=KV.wallet.web3();b.w3contract=new f.eth.Contract(e,b.contract_address);d()})["catch"](function(e){c(e)})})};
