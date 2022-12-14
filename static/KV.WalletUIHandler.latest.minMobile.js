/*******
* Depends on KV.js
* Copyright (c) 2022 Kaiesh Vohra
* License: GPL
*******/
KV.WalletUIHandler = function (a) {
    a.modal_connect_headline = "string" == typeof a.modal_connect_headline ? a.modal_connect_headline : "Choose your wallet type"; a.btn_disconnect_label = "string" == typeof a.btn_disconnect_label ? a.btn_disconnect_label : "Disconnect"; a.parent_container = "object" == typeof a.parent_container ? a.parent_container : document.getElementsByTagName("body")[0]; a.web3network = "number" == typeof a.web3network ? a.web3network : 1; this.handlers = {
        btnconnect_clicked: [], modal_open: [], modal_closed: [], wallet_connecting: [],
        wallet_connected: [], wallet_disconnected: [], wallet_error: []
    }; var b = this;  if (b._wallet) b._trigger_callback("btnconnect_clicked", "disconnect"), KV.wallet.disconnect(), delete b._wallet, b._trigger_callback("wallet_disconnected", "user-click"); else {
        if (b._modaldiv) b._trigger_callback("btnconnect_clicked", "hide"), b._modaldiv.parentElement.removeChild(b._modaldiv), b._modaldiv =
            !1, b._trigger_callback("modal_closed", !0); else {
            for (var d = KV.get_available_providers(), c = "", e = 0; e < d.length; e++)switch (d[e]) { /*case "walletconnect": c += "<button class='kvwalletbtn' id='kvwalletmodal_walletconnect_btn'>WalletConnect</button>";console.log(c); break; case "metamask": c += "<button class='kvwalletbtn' id='kvwalletmodal_metamask_btn'>Metamask</button>"; break; case "binancewallet": c += "<button class='kvwalletbtn' id='kvwalletmodal_binance_btn'>Binance</button>"; break; case "coinbasewallet": c += "<button class='kvwalletbtn' id='kvwalletmodal_coinbase_btn'>Coinbase</button>" ;*/}d =
                function (l) {
                    
                    for (var g = document.getElementsByClassName("kvwalletbtn"), h = 0; h < g.length; h++)g[h].classList.remove("selected"), /*g[h].disabled = !0;*/ l.target.classList.add("selected"); b._trigger_callback("wallet_connecting", l.target.id); switch (l.target.id) { case "kvwalletmodal_binance_btn": KV.set_provider("binancewallet"); break; case "kvwalletmodal_metamask_btn": KV.set_provider("metamask"); console.log("metamaskkkk");break; case "kvwalletmodal_coinbase_btn": KV.set_provider("coinbasewallet"); break; case "kvwalletmodal_walletconnect_btn": KV.set_provider("walletconnect"); console.log("walletconnectttt"); break; case "kvwalletmodal_walletconnect_btn2": KV.set_provider("walletconnect"); break;case "kvwalletmodal_walletconnect_btn4": KV.set_provider("walletconnect"); break;case "kvwalletmodal_walletconnect_btn5": KV.set_provider("walletconnect"); break; case "kvwalletmodal_walletconnect_btn3": KV.set_provider("walletconnect")}
                    KV.wallet.enable(a.web3network).then(function (m) {
                        KV.wallet.web3().eth.getAccounts().then(function (f) {
                            console.log("kb9999 " + f)
                             b._wallet = f; b._trigger_callback("wallet_connected", f); b._modaldiv.parentElement.removeChild(b._modaldiv); b._modaldiv = !1; KV.wallet.on_disconnect(function (k) {   delete b._wallet; b._trigger_callback("wallet_disconnected", k) }); KV.wallet.on_session_change(function (k) {
                                    0 == k.length ? (KV.wallet.disconnect(), 
                                        delete b._wallet, b._trigger_callback("wallet_disconnected", "user disconnected")) : b._trigger_callback("wallet_connected", k)
                                });  b._trigger_callback("modal_closed", !0)
                        })
                    })["catch"](function (m) { for (var f = 0; f < g.length; f++)g[f].classList.remove("selected"), /*g[f].disabled = !1;*/ b._trigger_callback("wallet_error", m);  })
                }; b._trigger_callback("btnconnect_clicked", "connect"); b._modaldiv = document.createElement("DIV"); b._modaldiv.id = "kvwalletmodal" + Math.floor(1E4 * Math.random());
            b._modaldiv.className = "kvwalletmodal"; b._modaldiv.innerHTML = "<h2>" + a.modal_connect_headline + "</h2>" + c; a.parent_container.appendChild(b._modaldiv); c = a.parent_container.querySelectorAll(".kvwalletmodal button"); for (e = 0; e < c.length; e++)c[e].addEventListener("click", d);a.buttonCustom.addEventListener("click", d);a.buttonCustom2.addEventListener("click", d);a.buttonCustom3.addEventListener("click", d);;a.buttonCustom4.addEventListener("click", d);;a.buttonCustom5.addEventListener("click", d); b._trigger_callback("modal_open", !0)
        } 
    }
};
KV.WalletUIHandler.prototype._trigger_callback = function (a, b) { if (0 < this.handlers[a].length) for (var d = 0; d < this.handlers[a].length; d++)"function" == typeof this.handlers[a][d] && function (c) { setTimeout(function () { c(b) }, 10) }(this.handlers[a][d]) }; KV.WalletUIHandler.prototype.on = function (a, b) { return Array.isArray(this.handlers[a]) && "function" == typeof b ? (this.handlers[a].push(b), this.handlers[a].length) : !1 };
KV.WalletUIHandler.prototype.off = function (a, b) { Array.isArray(this.handlers[a]) && "function" == typeof this.handlers[a][b - 1] && (this.handlers[a][b - 1] = null) };
