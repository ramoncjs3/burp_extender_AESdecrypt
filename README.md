# burp_extender_AESdecrypt
报文加解密插件，基于个人DESdecrypt项目魔改

如下图所示：
1. 整个body部分进行加解密，DESdecrypt插件中对指定参数部分进行修改，修改后也不用在新标签页内填写param了，没用到。
2. response是json格式，对json内容进行提取，对msgdata部分进行解密，如整体修改见上面修改前的部分。
3. 此站情况略有不同，des解开之后还要再解一层lzstring压缩，js的库，jython加载python改写库失败，索性直接通过python在v8里执行js了，速度还可以。
[图片](https://github.com/ramoncjs3/burp_extender_AESdecrypt/blob/main/123.jpg)
