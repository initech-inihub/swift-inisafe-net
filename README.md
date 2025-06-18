# swift-inisafe-net

## OverView
INISAFE MobilianNet for iOS 는 iOS 기반에서 PKI를 지원하기 위한 솔루션으로 iOS 기반의 application 개발 시 필요한 PKI기반 기술을 API 형식으로 제공

## Features
`HandShake`: 일종의 비대칭키 암호화로 서버와 클라이언트 모두 session key를 만드는데 참여를 하는 프로토콜
session key를 공유하기 위해 handshake 과정을 거치며 공유된 session key를 이용하여 암/복호화를 수행합니다. 암호화 된 데이터는 서버측 옵션 “HS_PAD_LEN”, “HS_CHECK_INTEGRITY” 의 설정 에 따라 암호화 정책으로 클라이언트와 공유되며
En ( Hash(msg)[optional] | random[optional] | msg)의 포맷으로 전송

## Usage
1. 라인센스 발급
2. Package Dependencies 추가
```swift
  import InisafeNet

  var inisafeNet = InisafeNet()
  _ = inisafeNet.initialize(type: 0x02, configPath: "", licensePath: "") //Server: 0x01, Client: 0x02
  _ = inisafeNet.handshakeManager().initHandshake(ctx: nil, inputPtr: nil, inputLen: Int32(0))

or

  var inisafeNet = InisafeNet()
  _ = inisafeNet.initialize(type: 0x02, configPath: "", licensePath: "")

  var hand = inisafeNet.handshakeManager()
  _ = hand.initHandshake(ctx: nil, inputPtr: nil, inputLen: 08)
```
