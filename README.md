# -KISIA-pcap-test
<strong>report pcap test</strong><br><br>
<Strong>과제</strong><br>
송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.<br>
<ol>
  <li>Ethernet Header의 src mac / dst mac</li>
  <li>IP Header의 src ip / dst ip</li>
  <li>TCP Header의 src port / dst port</li>
  <li>Payload(Data)의 hexadecimal value(최대 10바이트까지만)</li>
</ol>

# Ethernet Header
<ul>
  <li><strong>DA, SA, LenTYPE</strong> : MAC HEADER</li>
  <li><strong>DATA</strong> : DATAGRAM</li>
  <li>패킷 트레이서로 캡처 받는 부분은 DA~DATA</li>
  <li><strong>Preamble</strong> :<br>동기화에 사용되는 64bit 필드, (0, 1) 구성. 네트워크 장치가 패킷 받아 이더넷 프레임의 시작 부분을 결정하고 동기화 할 때 사용.</li>
  <li><strong>DA (Destination Address)</strong> : 목적지 시스템의 이더넷 주소.</li>
  <li><strong>SA (Source Address)</strong> : 패킷을 전송하는 호스트의 이더넷 주소.</li>
  <li><strong>Type</strong> : 이더넷 프레임 상단의 데이터 종류.</li>
  <li><strong>FCS</strong> :<br>에러 검출을 위해 사용되는 필드. 송/수신 측 호스트 시스템에 의해 프레임에 포함되는 내용을 계산한 값. 값이 다르면 해당 프레임 무시.</li>
</ul>
<pre><code>struct eth_hdr {
	uint8_t DA[ETH_ALEN]; // DA => Target Ethernet Adr
	uint8_t SA[ETH_ALEN]; // SA => Host Ethernet Adr
	uint16_t DT; // Data type
	uint8_t PI[0]; // Proctocol Inf
} __attribute__((packed));
</code></pre>

# IP Header
<ul>
  <li><strong>Version</strong> : TCP/IP 제품은 IPv4를 사용.</li>
  <li><strong>Header Length</strong> : <br>IP 헤드의 길이를 32비트 단위로 나타냄. 대부분의 IP 헤더 길이는 20바이트.<br>필드 값은 거의 항상 5.</li>
  <li><strong>Type-of-Service Flags</strong> : 서비스의 우선 순위를 제공.</li>
  <li><strong>Total Packet Length</strong> : 전체 IP 패킷 길이를 바이트 단위로 나타냄.</li>
  <li><strong>Fragment Identifier</strong> : 분열이 발생한 경우, 조각을 다시 결합, 원래의 데이터를 식별하기 위해 사용.</li>
  <li>
  <strong>Fragment Flags</strong>
  : 첫 1bit는 항상 0 설정, 나머지 2비트의 용도는 다음과 같음.
    <ol>
      <li>
        May Fragment : IP 라우터에 의해 분열된 여부.<br>
        (플래그 0 - 분열가능 1 - 분열 방지)
      </li>
      <li>
        More Fragment : 원래 데이터의 분열 조각 더 있는지 판단.<br>
        (플래그 0 - 마지막 조각, 기본값 1 - 조각 더 있음.
      </li>
    </ol>
  </li>
  <li><strong>Fragmentation Offset</strong> : 8바이트 오프셋으로 조각에 저장된 원래 데이터의 바이트 범위.</li>
  <li><strong>Time-to-Live</strong> : <br>데이터를 전달할 수 없는 것으로 판단되어 소멸되기 전 데이터가 이동할 수 있는 단계의 수를 나타냄. Time-to-Live 필드는 1~255 사이 값을 지정하며 라우터들은 패킷을 전달 할 때 마다 이 값을 하나씩 감소시킴.</li>
  <li>
    <strong>Protocol Identifier</strong> : 상위 계층 프로토콜
    <ol>
      <li>1 - ICMP</li>
      <li>2 - IGMP</li>
      <li>6 - TCP</li>
      <li>17 - UDP</li>
    </ol>
  </li>
  <li><strong>Header Checksum</strong> : IP 헤더의 체크섬을 저장, 라우터를 지나갈 때 마다 재 계산을 해서 속도가 떨어짐.</li>
  <li><strong>Source IP Address</strong> : 출발지 IP 주소.</li>
  <li><strong>Destination IP Address</strong> : 목적지 IP 주소.</li>
  <li><strong>Option</strong> : Type-of-Service 플래그처럼 특별한 처리 옵션을 추가로 정의 가능.</li>
</ul>
<pre><code>struct ipv4_hdr {
	uint8_t VIHL; // Version + IHL(Header Length)
	uint8_t TOS; // Typte Of Service
	uint16_t TL; // Total Length
	uint16_t ID; // Identification
	uint16_t FF; // Fragment Offset
	uint8_t TTL; // Time-to-live
	uint8_t PRI; // Protocol Identifier
	uint16_t HC; // Header Checksum
	uint8_t SIA[4]; // SIA => Source IP Address
	uint8_t DIA[4]; // DIA => Destination IP Address
	uint8_t INF[0];
} __attribute__((packed));
</code></pre>

# TCP Header
<ul>
  <li><strong>Source Port / Destination Port</strong> : 출발지 포트와 목적지 포트.</li>
  <li><strong>Sequence Number</strong> : 올바른 순서로 데이터를 보내기 위한 고유 일련번호.</li>
  <li><strong>Acknowledgement Number</strong> : 다음 세그먼트를 수신할 준비가 된 상태를 나타내는 번호.</li>
  <li><strong>Header Length</strong> : Header 길이를 32bit 단위로 나타냄. 최소 필드값 20Bytes.</li>
  <li><strong>Control Flag</strong> : 6개의 segment 상태를 나타내기 위한 공간. (0,1 표시)</li>
  <li><strong>Window Size</strong> : TCP segment의 내용 유효 검증.</li>
</ul>
<pre><code>struct tcp_hdr {
	uint16_t SP; // Source Port
	uint16_t DP; // Destination Port
	uint32_t SN; // Sequence Number
	uint32_t AN; // Acknowledgement Number
	uint16_t DRF; // Header Length + Reserved + Code Bits
	uint16_t WSF; // Windows Size Field
	uint16_t CH; // Checksum
	uint16_t UR; // Urgent
	uint8_t payload[0];
} __attribute__((packed));
</code></pre>

# Preview






