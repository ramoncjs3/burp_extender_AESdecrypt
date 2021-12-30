# -*- coding: utf-8 -*-
# Author: Ramoncjs
# Time: 2021/12/30

import base64
from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import SecretKeySpec

secret_key = '757da2be61249c188319a9269f1a6ccb'
iv = '4490d2ded4f2d4ad'


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerMessageEditorTabFactory(self)

    # 实现IMessageEditorTabFactory方法
    # Burp 将会对每一个 HTTP 消息编辑器调用一次此方法，此工厂必须返回一个新的 IMessageEditorTab 对象
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return DataInputTab(self, controller, editable)


# 实现 IMessageEditorTab
class DataInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._helpers = extender._helpers
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.aes_crypto = aes_crypto()

    # 实现Itab接口
    def getTabCaption(self):
        return 'Des Decrypt'

    # 调用此方法获取自定义标签页显示的组件
    def getUiComponent(self):
        return self._txtInput.getComponent()

    # 在显示一个新的 HTTP 消息时，启用自定义的标签页
    def isEnabled(self, content, isRequest):
        r = self._helpers.analyzeResponse(content)
        msg = content[r.getBodyOffset():].tostring()
        # enable this tab for requests containing a data parameter
        if isRequest:
            return isRequest
        elif not isRequest:
            return (not isRequest and not msg is None)

    # 此方法用于将一个 HTTP 消息显示在编辑器中
    def setMessage(self, content, isRequest):
        r = self._helpers.analyzeResponse(content)
        self.request_header = r.getHeaders()
        msg = content[r.getBodyOffset():].tostring()
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            if isRequest:
                aa = {}
                bb = ""
                for em, i in enumerate(self._extender._helpers.analyzeRequest(content).getParameters()):
                    if i.getType() == IParameter.PARAM_BODY:
                        aa[i.getName()] = self.aes_crypto.decryptJython(self._extender._helpers.urlDecode(i.getValue()))
                for xx, vv in aa.items():
                    bb += xx + "=" + vv + "&"
                self._txtInput.setText(bb)
                self._txtInput.setEditable(self._editable)
            elif not isRequest:
                pass
        self._currentMessage = content

    # 此方法用于获取当前已显示的消息，此消息可能已被用户修改
    def getMessage(self):
        # 用户是否修改编辑器内容
        global new_req

        if self._txtInput.isTextModified():
            # reserialize the data
            text = self._txtInput.getText()
            encodebody = ""
            # 输入字符串默认转换成burp数组格式,加密需进行格式转换,注意:byte转换成string后无需再次转换回去
            a = self._extender._helpers.bytesToString(text)
            for i in a.split("&"):
                if i != '':
                    encodebody += "{0}={1}&".format(i.split("=")[0], self._extender._helpers.urlEncode(
                        self.aes_crypto.encryptJython(i.split("=")[1])))
            try:
                new_req = self._extender._helpers.buildHttpMessage(self.request_header, encodebody)
            except Exception as e:
                print(e)
            return new_req

    # 此方法用于指示用户是否对编辑器的内容做了修改
    def isModified(self):
        return self._txtInput.isTextModified()

    # 直接返回 iTextEditor 中选中的文本
    def getSelectedData(self):
        return self._txtInput.getSelectedText()


# DES加解密脚本
class aes_crypto():
    def encryptJython(self, payload):
        aesKey = SecretKeySpec(secret_key, "AES")
        aesIV = IvParameterSpec(iv)
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIV)
        encrypted = cipher.doFinal(payload)
        return base64.b64encode(encrypted)

    def decryptJython(self, payload):
        decoded = base64.b64decode(payload)
        aesKey = SecretKeySpec(secret_key, "AES")
        aesIV = IvParameterSpec(iv)
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, aesIV)
        decrypted = cipher.doFinal(decoded)
        return decrypted.tostring()
