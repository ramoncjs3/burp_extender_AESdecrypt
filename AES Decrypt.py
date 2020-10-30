# -*- coding: utf-8 -*-
# Author: Ramoncjs
# Time: 2020/10/30
import sys
import json
import execjs
from binascii import b2a_hex, a2b_hex
from burp import IProxyListener
from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import ITab
from burp import IHttpRequestResponse
import java.lang as lang
from java.awt import Color
from java.awt import Font
from javax import swing
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import SecretKeySpec

param = 'nullnull'
secret_key = 'nullnull'
iv = 'nullnull'


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener, ITab, IHttpRequestResponse):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AES Decrypt")
        # 初始化UI
        self.TabUI()
        self._callbacks.addSuiteTab(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)

    # 实现IMessageEditorTabFactory方法
    # Burp 将会对每一个 HTTP 消息编辑器调用一次此方法，此工厂必须返回一个新的 IMessageEditorTab 对象
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return DataInputTab(self, controller, editable)

    # 实现Itab接口
    def getTabCaption(self):
        return 'AES Decrypt'

    def getUiComponent(self):
        return self.tab

    # 实现新窗口功能与UI
    def TabUI(self):
        self.tab = swing.JPanel()
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)

        self.titleLabel = swing.JLabel("AES Plugin")
        self.titleLabel.setFont(Font("Tahoma", 1, 16))
        self.titleLabel.setForeground(Color(135, 206, 250))

        self.infoLabel = swing.JLabel("Please enter the parameters to be decrypted and AES's Key and IV.")
        self.infoLabel.setFont(Font("Tahoma", 0, 12))

        self.keyLabel = swing.JLabel("AES Plugin Params")
        self.keyLabel.setFont(Font("Tahoma", 1, 12))

        self.setKeyTextArea = swing.JTextArea("")
        self.setIVTextArea = swing.JTextArea("")
        self.setParamTextArea = swing.JTextArea("")

        self.setkeyButton = swing.JButton("  setKey   ", actionPerformed=self.setKey)
        self.setIVButton = swing.JButton("   setIV    ", actionPerformed=self.setIV)
        self.setParamButton = swing.JButton("setParam", actionPerformed=self.setParam)

        self.logLabel = swing.JLabel("Log")
        self.logLabel.setFont(Font("Tahoma", 1, 12))

        self.logPane = swing.JScrollPane()
        self.logArea = swing.JTextArea("Logs.\n")
        self.logArea.setLineWrap(True)
        self.logPane.setViewportView(self.logArea)

        self.logClearButton = swing.JButton("   Clear    ", actionPerformed=self.logClear)
        self.getParamsButton = swing.JButton("getParams", actionPerformed=self.getParams)

        self.bar = swing.JSeparator(swing.SwingConstants.HORIZONTAL)
        self.bar2 = swing.JSeparator(swing.SwingConstants.HORIZONTAL)

        # 设置水平布局
        # .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                          .addGap(15)
                          .addGroup(layout.createParallelGroup()
                                    .addComponent(self.titleLabel)
                                    .addComponent(self.infoLabel)
                                    .addComponent(self.bar)
                                    .addComponent(self.keyLabel)
                                    .addGroup(layout.createSequentialGroup()
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.setkeyButton)
                                                        .addComponent(self.setIVButton)
                                                        .addComponent(self.setParamButton))
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.setKeyTextArea,
                                                                      swing.GroupLayout.PREFERRED_SIZE, 300,
                                                                      swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(self.setIVTextArea,
                                                                      swing.GroupLayout.PREFERRED_SIZE, 300,
                                                                      swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(self.setParamTextArea,
                                                                      swing.GroupLayout.PREFERRED_SIZE, 300,
                                                                      swing.GroupLayout.PREFERRED_SIZE))
                                              )
                                    .addComponent(self.bar2)
                                    .addComponent(self.logLabel)
                                    .addGroup(layout.createSequentialGroup()
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.logClearButton)
                                                        .addComponent(self.getParamsButton)
                                                        )
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE,
                                                                      300, swing.GroupLayout.PREFERRED_SIZE)))
                                    ))

        )

        # 设置垂直布局
        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                          .addGap(15)
                          .addComponent(self.titleLabel)
                          .addGap(10)
                          .addComponent(self.infoLabel)
                          .addGap(30)
                          .addComponent(self.bar)
                          .addGap(10)
                          .addComponent(self.keyLabel)
                          .addGap(20)
                          .addGroup(layout.createSequentialGroup()
                                    .addGroup(layout.createParallelGroup()
                                              .addGroup(layout.createParallelGroup()
                                                        .addGroup(layout.createSequentialGroup()
                                                                  .addComponent(self.setkeyButton)
                                                                  .addGap(20)
                                                                  .addComponent(self.setIVButton)
                                                                  .addGap(20)
                                                                  .addComponent(self.setParamButton))
                                                        )
                                              .addGroup(layout.createParallelGroup()
                                                        .addGroup(layout.createSequentialGroup()
                                                                  .addComponent(self.setKeyTextArea,
                                                                                swing.GroupLayout.PREFERRED_SIZE, 30,
                                                                                swing.GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(20)
                                                                  .addComponent(self.setIVTextArea,
                                                                                swing.GroupLayout.PREFERRED_SIZE, 30,
                                                                                swing.GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(20)
                                                                  .addComponent(self.setParamTextArea,
                                                                                swing.GroupLayout.PREFERRED_SIZE, 30,
                                                                                swing.GroupLayout.PREFERRED_SIZE))
                                                        )
                                              )
                                    )
                          .addGap(40)
                          .addComponent(self.bar2)
                          .addGap(10)
                          .addComponent(self.logLabel)
                          .addGap(10)
                          .addGroup(layout.createParallelGroup()
                                    .addGroup(layout.createSequentialGroup()
                                              .addComponent(self.getParamsButton)
                                              .addGap(20)
                                              .addComponent(self.logClearButton)

                                              )
                                    .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 500,
                                                  swing.GroupLayout.PREFERRED_SIZE))
                          )
        )

    def setKey(self, key):
        global secret_key
        pubText = self.setKeyTextArea.getText().strip('\n')
        if pubText != None and len(pubText) > 0:
            status = False
            try:
                secret_key = str((pubText).encode("utf-8"))
                status = True
            except:
                pass
            self.logPrint(status, 'secret_key:' + secret_key)

    def setIV(self, setiv):
        global iv
        pubText = self.setIVTextArea.getText().strip('\n')
        if pubText != None and len(pubText) > 0:
            status = False
            try:
                iv = str((pubText).encode("utf-8"))
                status = True
            except:
                pass
            self.logPrint(status, 'iv:' + iv)

    def setParam(self, setparam):
        global param
        pubText = self.setParamTextArea.getText().strip('\n')
        if pubText != None and len(pubText) > 0:
            status = False
            try:
                param = str((pubText).encode("utf-8"))
                status = True
            except:
                pass
            self.logPrint(status, 'param:' + param)

    def logClear(self, log):
        self.logArea.setText("")

    def getParams(self, params):
        status = True
        try:
            self.logPrint(status, 'secret_key:' + secret_key)
            self.logPrint(status, 'iv:' + iv)
            self.logPrint(status, 'param:' + param)
        except:
            pass

    def logPrint(self, status, data):
        statusList = ["[!] Failure: ", "[+] Success: "]
        message = statusList[status] + data
        self.logArea.append(message + '\n')

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self.messageInfo = messageInfo


# 实现 IMessageEditorTab
class DataInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._helpers = extender._helpers
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.lz = lzstring()

    # 此方法用于获取自定义标签的标题文本
    def getTabCaption(self):
        return "unCrypto"

    # 调用此方法获取自定义标签页显示的组件
    def getUiComponent(self):
        return self._txtInput.getComponent()

    # 在显示一个新的 HTTP 消息时，启用自定义的标签页
    def isEnabled(self, content, isRequest):
        # 响应体内容
        r = self._helpers.analyzeResponse(content)
        msg = content[r.getBodyOffset():].tostring()

        # enable this tab for requests containing a data parameter
        if isRequest:
            return isRequest  # (isRequest and not self._extender._helpers.getRequestParameter(content, "%s" % (param)) is None)
        elif not isRequest:
            return (not isRequest and not msg is None)

    # 此方法用于将一个 HTTP 消息显示在编辑器中
    # 请求体内容
    def setMessage(self, content, isRequest):
        r = self._helpers.analyzeRequest(content)
        msg = content[r.getBodyOffset():].tostring()
        self.request_header = r.getHeaders()
        self._currentMessage = content
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            if isRequest:
                # 检索关键参数
                # parameter = self._extender._helpers.getRequestParameter(content, "%s" % (param))
                # a参数值
                # 如果加密数据部分存在+号，则urldecode会将+解析为" ",无法正常解密
                # a = self._extender._helpers.urlDecode(parameter.getValue())
                # a = parameter.getValue()
                # 使用解密函数将原信息进行解密
                try:
                    b = aes_crypto().decryptJython(msg)
                    b = self.lz.decodebase64(b)
                    # setText此方法用于更新编辑器中当前已显示的文本
                    self._txtInput.setText(b)
                    # setEditable此方法用于决定当前的编辑器是否可编辑
                    self._txtInput.setEditable(self._editable)
                except Exception as e:
                    print(e)

            elif not isRequest:
                try:
                    c = aes_crypto().decryptJython(json.loads(msg)['MsgData'])
                    c = self.lz.decodebase64(c)
                    # setText此方法用于更新编辑器中当前已显示的文本
                    self._txtInput.setText(c)
                    # setEditable此方法用于决定当前的编辑器是否可编辑
                    self._txtInput.setEditable(self._editable)
                except Exception as e:
                    print(e)

    # 此方法用于获取当前已显示的消息，此消息可能已被用户修改
    def getMessage(self):
        # 用户是否修改编辑器内容
        if self._txtInput.isTextModified():
            # reserialize the data
            text = self._txtInput.getText()
            # 输入字符串默认转换成burp数组格式,加密需进行格式转换,注意:byte转换成string后无需再次转换回去！！！大坑！
            a = self._extender._helpers.bytesToString(text)
            # 添加lz-string编码

            b = self.lz.encodebase64(a)
            b = aes_crypto().encryptJython(str(b.encode("utf-8")))
            # 如果加密数据部分存在+号，则urldecode会将+解析为" ",无法正常解密
            # input = self._extender._helpers.urlEncode(b)
            # update the request with the new parameter value
            # 新增对get方法的修改
            try:
                if (self._helpers.analyzeRequest(self._currentMessage).getMethod()) == "GET":
                    self.method = IParameter.PARAM_URL
                    print(self.method)
                else:
                    self.method = IParameter.PARAM_BODY
            except Exception as e:
                print(e)
            # return self._extender._helpers.updateParameter(self._currentMessage,self._extender._helpers.buildParameter("%s" % (param), b,self.method))
            encodebody = self._extender._helpers.stringToBytes(b)
            try:
                new_req = self._extender._helpers.buildHttpMessage(self.request_header, encodebody)
                # tt = self._currentMessage.setRequest(new_req) TMD!坑逼...
            except Exception as e:
                print(e)
            return new_req

        else:
            return self._currentMessage

    # 此方法用于指示用户是否对编辑器的内容做了修改
    def isModified(self):
        return self._txtInput.isTextModified()

    # 直接返回 iTextEditor 中选中的文本
    def getSelectedData(self):
        return self._txtInput.getSelectedText()


# AES 加密脚本

class aes_crypto():
    def encryptJython(self, payload):
        aesKey = SecretKeySpec(secret_key, "AES")
        aesIV = IvParameterSpec(iv)
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIV)
        encrypted = cipher.doFinal(payload)
        return b2a_hex(encrypted)

    def decryptJython(self, payload):
        decoded = a2b_hex(payload)
        aesKey = SecretKeySpec(secret_key, "AES")
        aesIV = IvParameterSpec(iv)
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, aesIV)
        decrypted = cipher.doFinal(decoded)
        return decrypted.tostring()


class lzstring():
    def decodebase64(self, msg):
        self.js_compile = execjs.compile("""
    var LZString = function () {
    function a(a, b) {
        if (!c[a]) {
            c[a] = {};
            for (var d = 0; d < a.length; d++) c[a][a.charAt(d)] = d
        }
        return c[a][b]
    }
    var b = String.fromCharCode,
        c = {},
        d = {
            compressToBase64: function (a) {
                if (null == a) return "";
                a = d._compress(a, 6, function (a) {
                    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\x3d".charAt(a)
                });
                switch (a.length % 4) {
                    default:
                    case 0:
                        return a;
                case 1:
                    return a + "\x3d\x3d\x3d";
                case 2:
                    return a + "\x3d\x3d";
                case 3:
                    return a + "\x3d"
                }
            }, decompressFromBase64: function (b) {
                return null == b ? "" : "" ==
                    b ? null : d._decompress(b.length, 32, function (c) {
                        return a("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\x3d", b.charAt(c))
                    })
            }, compressToUTF16: function (a) {
                return null == a ? "" : d._compress(a, 15, function (a) {
                    return b(a + 32)
                }) + " "
            }, decompressFromUTF16: function (a) {
                return null == a ? "" : "" == a ? null : d._decompress(a.length, 16384, function (b) {
                    return a.charCodeAt(b) - 32
                })
            }, compressToUint8Array: function (a) {
                a = d.compress(a);
                for (var b = new Uint8Array(2 * a.length), c = 0, h = a.length; h > c; c++) {
                    var m = a.charCodeAt(c);
                    b[2 * c] = m >>> 8;
                    b[2 * c + 1] = m % 256
                }
                return b
            }, decompressFromUint8Array: function (a) {
                if (null === a || void 0 === a) return d.decompress(a);
                for (var c = Array(a.length / 2), g = 0, h = c.length; h > g; g++) c[g] = 256 * a[2 * g] + a[2 * g + 1];
                var m = [];
                return c.forEach(function (a) {
                    m.push(b(a))
                }), d.decompress(m.join(""))
            }, compressToEncodedURIComponent: function (a) {
                return null == a ? "" : d._compress(a, 6, function (a) {
                    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$".charAt(a)
                })
            }, decompressFromEncodedURIComponent: function (b) {
                return null ==
                    b ? "" : "" == b ? null : (b = b.replace(/ /g, "+"), d._decompress(b.length, 32, function (c) {
                        return a("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$", b.charAt(c))
                    }))
            }, compress: function (a) {
                return d._compress(a, 16, function (a) {
                    return b(a)
                })
            }, _compress: function (a, b, c) {
                if (null == a) return "";
                var d, m, n, p = {},
                    r = {},
                    s = "",
                    t = "",
                    v = "",
                    u = 2,
                    z = 3,
                    x = 2,
                    w = [],
                    y = 0,
                    A = 0;
                for (n = 0; n < a.length; n += 1)
                    if (s = a.charAt(n), Object.prototype.hasOwnProperty.call(p, s) || (p[s] = z++, r[s] = !0), t = v + s, Object.prototype.hasOwnProperty.call(p, t)) v =
                        t;
                    else {
                        if (Object.prototype.hasOwnProperty.call(r, v)) {
                            if (256 > v.charCodeAt(0)) {
                                for (d = 0; x > d; d++) y <<= 1, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++;
                                m = v.charCodeAt(0);
                                for (d = 0; 8 > d; d++) y = y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1
                            } else {
                                m = 1;
                                for (d = 0; x > d; d++) y = y << 1 | m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m = 0;
                                m = v.charCodeAt(0);
                                for (d = 0; 16 > d; d++) y = y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1
                            }
                            u--;
                            0 == u && (u = Math.pow(2, x), x++);
                            delete r[v]
                        } else
                            for (m = p[v], d = 0; x > d; d++) y = y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1;
                        u--;
                        0 == u && (u = Math.pow(2, x), x++);
                        p[t] = z++;
                        v = String(s)
                    }
                if ("" !== v) {
                    if (Object.prototype.hasOwnProperty.call(r, v)) {
                        if (256 > v.charCodeAt(0)) {
                            for (d = 0; x > d; d++) y <<= 1, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++;
                            m = v.charCodeAt(0);
                            for (d = 0; 8 > d; d++) y = y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1
                        } else {
                            m = 1;
                            for (d = 0; x > d; d++) y = y << 1 | m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m = 0;
                            m = v.charCodeAt(0);
                            for (d = 0; 16 > d; d++) y = y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1
                        }
                        u--;
                        0 == u && (u = Math.pow(2, x), x++);
                        delete r[v]
                    } else
                        for (m = p[v], d = 0; x > d; d++) y =
                            y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1;
                    u--;
                    0 == u && (Math.pow(2, x), x++)
                }
                m = 2;
                for (d = 0; x > d; d++) y = y << 1 | 1 & m, A == b - 1 ? (A = 0, w.push(c(y)), y = 0) : A++, m >>= 1;
                for (;;) {
                    if (y <<= 1, A == b - 1) {
                        w.push(c(y));
                        break
                    }
                    A++
                }
                return w.join("")
            }, decompress: function (a) {
                return null == a ? "" : "" == a ? null : d._decompress(a.length, 32768, function (b) {
                    return a.charCodeAt(b)
                })
            }, _decompress: function (a, c, d) {
                var h, m, n, p, r, s, t = [],
                    v = 4,
                    u = 4,
                    z = 3;
                m = "";
                var x = [],
                    w = d(0),
                    y = c,
                    A = 1;
                for (h = 0; 3 > h; h += 1) t[h] = h;
                m = 0;
                p = Math.pow(2, 2);
                for (r = 1; r != p;) n = w & y, y >>= 1, 0 == y &&
                    (y = c, w = d(A++)), m |= (0 < n ? 1 : 0) * r, r <<= 1;
                switch (m) {
                case 0:
                    m = 0;
                    p = Math.pow(2, 8);
                    for (r = 1; r != p;) n = w & y, y >>= 1, 0 == y && (y = c, w = d(A++)), m |= (0 < n ? 1 : 0) * r, r <<= 1;
                    s = b(m);
                    break;
                case 1:
                    m = 0;
                    p = Math.pow(2, 16);
                    for (r = 1; r != p;) n = w & y, y >>= 1, 0 == y && (y = c, w = d(A++)), m |= (0 < n ? 1 : 0) * r, r <<= 1;
                    s = b(m);
                    break;
                case 2:
                    return ""
                }
                h = t[3] = s;
                for (x.push(s);;) {
                    if (A > a) return "";
                    m = 0;
                    p = Math.pow(2, z);
                    for (r = 1; r != p;) n = w & y, y >>= 1, 0 == y && (y = c, w = d(A++)), m |= (0 < n ? 1 : 0) * r, r <<= 1;
                    switch (s = m) {
                    case 0:
                        m = 0;
                        p = Math.pow(2, 8);
                        for (r = 1; r != p;) n = w & y, y >>= 1, 0 == y && (y = c, w = d(A++)), m |= (0 <
                            n ? 1 : 0) * r, r <<= 1;
                        t[u++] = b(m);
                        s = u - 1;
                        v--;
                        break;
                    case 1:
                        m = 0;
                        p = Math.pow(2, 16);
                        for (r = 1; r != p;) n = w & y, y >>= 1, 0 == y && (y = c, w = d(A++)), m |= (0 < n ? 1 : 0) * r, r <<= 1;
                        t[u++] = b(m);
                        s = u - 1;
                        v--;
                        break;
                    case 2:
                        return x.join("")
                    }
                    if (0 == v && (v = Math.pow(2, z), z++), t[s]) m = t[s];
                    else {
                        if (s !== u) return null;
                        m = h + h.charAt(0)
                    }
                    x.push(m);
                    t[u++] = h + m.charAt(0);
                    v--;
                    h = m;
                    0 == v && (v = Math.pow(2, z), z++)
                }
            }
        };
    return d
}();
    """)
        tt = self.js_compile.call('LZString.decompressFromBase64', msg)
        return tt

    def encodebase64(self, msg):
        tt = self.js_compile.call('LZString.compressToBase64', msg)
        return (tt)
