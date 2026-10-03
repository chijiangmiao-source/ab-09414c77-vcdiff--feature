# 深空归档 · 增量标定片导入校验台（VCDIFF RFC 3284）

零运行时依赖的 Node.js 服务：归档工程师在页面粘贴 **Base64 VCDIFF 载荷**（≤ 128 KiB）
与 **Base64 基准字典**（≤ 64 KiB），提交到真实解码接口后查看：

- 最终字节长度与 SHA-256；
- 每个窗口的源区间（SOURCE 基准字典 / TARGET 前序窗口输出 / 无源段）；
- 按指令顺序列出的 ADD、RUN、COPY 证据（尺寸、数据 hex、地址模式、U 空间地址、
  解析后的实际指向区间、原始偏移）；
- 失败时给出错误码与**首个原始偏移**，且不保留任何部分输出；
- 可一键清空输入与结论。

## 严格接受规则（RFC 3284）

| 规则 | 实现 |
| --- | --- |
| 文件头 | 仅接受 `D6 C3 C4 00 00`，header4 必须为 0，保留位拒绝 |
| 码表 | 仅 RFC 3284 默认码表（s_near=4, s_same=3，9 种地址模式） |
| 二次压缩 | `VCD_DECOMPRESS` 头与 `VCD_DATACOMP/INSTCOMP/ADDRCOMP` 一律拒绝 |
| 窗口数 | 至多 8 个 |
| 输出上限 | 512 KiB（跨窗口累计，生成前校验） |
| 整数 | base-128 必须最短编码（前导 0 组 → `NON_MINIMAL_INTEGER`） |
| 段长度 | 数据/指令/地址三段长度必须恰好填满窗口 delta，否则 `SEGMENT_LENGTH` |
| COPY 地址 | 仅允许落在 SOURCE 段、前序 TARGET 输出或当前窗口**已生成**字节；逐字节拷贝支持自重叠；禁止跨越 S/T 边界 |
| 地址缓存 | 按窗口重置；`SELF / HERE / NEAR0..3 / SAME0..2` 全部实现 |
| 截断 | 头部、整数、窗口体、三段任意截断 → `TRUNCATED` |

所有错误都携带**流内绝对原始偏移**（`error.offset`），解码函数要么返回完整输出，要么抛错。

## 目录结构

```
src/vcdiff.js          RFC 3284 严格解码器（默认码表、地址缓存、证据收集）
src/server.js          零依赖 HTTP 服务（/healthz、/、/api/decode、/api/reset）
static/index.html      校验台页面（原生 JS，无外部资源）
test/vcdiff.test.js    解码器单元/拒绝用例（50 项）
test/server.test.js    接口测试
test/helpers/encoder.js 测试用最小 VCDIFF 编码器（可构造畸形流）
fixtures/golden/       open-vcdiff 参考实现生成的黄金向量（7 组）
fixtures/samples.json  页面/冒烟所用样本（含失败偏移）
scripts/generate-samples.js 重新生成样本
scripts/check-syntax.js     构建检查（node --check 全部 JS）
scripts/verify.js           单元测试 + 构建检查 + HTTP 冒烟，退出码结束
Dockerfile / docker-compose.yml
```

解码器已与 Google **open-vcdiff** 参考实现双向交叉验证：参考实现产出的黄金向量
（覆盖 SELF/HERE/NEAR0-3/SAME0-2、自重叠 COPY、多窗口、空字典）可逐字节还原；
测试编码器产出的流也能被参考实现解码器接受。

## 本地运行（需 Node.js ≥ 20）

```bash
npm test                 # 全部单元/接口测试
npm run check            # 构建检查
npm run samples          # 重新生成 fixtures/samples.json
HOST=0.0.0.0 PORT=8080 npm start
# 打开 http://localhost:8080/
```

## Docker Compose

```bash
# 启动页面与健康检查（宿主机端口可用 HOST_PORT 配置，默认 8080）
HOST_PORT=9090 docker compose up -d --build web
curl -s http://localhost:9090/healthz

# 一次性校验服务：单元测试 + 构建检查 + 对已就绪 web 服务的接口/HTTP 冒烟，
# 以退出码结束（0 成功）
docker compose run --build verify
echo "exit=$?"
```

## HTTP 接口

`POST /api/decode`

```json
{ "deltaBase64": "1sPExAAAAA...", "dictionaryBase64": "" }
```

成功 `200`：

```json
{
  "ok": true,
  "length": 37,
  "sha256": "ddd5ab03…",
  "windows": [
    {
      "index": 1,
      "source": { "kind": "TARGET", "position": 5, "length": 11 },
      "targetOffset": 24, "targetLength": 13,
      "sections": { "data": 3, "instructions": 4, "addresses": 3 },
      "instructions": [
        { "seq": 0, "op": "COPY", "size": 5, "mode": "SELF",
          "address": 5, "encoded": 5, "encodedOffset": 0,
          "range": { "area": "PRIOR_TARGET", "start": 10, "end": 15 },
          "overlaps": false, "codeOffset": 30 }
      ]
    }
  ],
  "limits": { "maxOutputBytes": 524288, "maxWindows": 8 }
}
```

失败 `400/413`：

```json
{ "ok": false, "error": { "code": "COPY_NOT_GENERATED", "message": "…", "offset": 39 } }
```

另有 `GET /healthz → {"status":"ok"}` 与 `POST /api/reset → {"ok":true}`。
