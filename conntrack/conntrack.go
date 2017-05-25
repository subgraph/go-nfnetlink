package conntrack

import (
	"github.com/subgraph/go-nfnetlink"
	"syscall"
	"net"
	"fmt"
	"bytes"
	"encoding/binary"
)

const (
	NF_NETLINK_CONNTRACK_NEW = 0x00000001
	NF_NETLINK_CONNTRACK_UPDATE = 0x00000002
	NF_NETLINK_CONNTRACK_DESTROY = 0x00000004

	NFNL_SUBSYS_CTNETLINK = 1
	IPCTNL_MSG_CT_NEW = 0

	CTA_TUPLE_ORIG = 1
	CTA_TUPLE_REPLY = 2
	CTA_STATUS = 3
	CTA_PROTOINFO = 4
	CTA_TIMEOUT = 7
	CTA_COUNTERS_ORIG= 9
	CTA_COUNTERS_REPLY = 10
	CTA_ID = 12

	CTA_TUPLE_IP = 1
	CTA_TUPLE_PROTO = 2

	CTA_IP_V4_SRC = 1
	CTA_IP_V4_DST = 2

	CTA_PROTO_NUM = 1
	CTA_PROTO_SRC_PORT = 2
	CTA_PROTO_DST_PORT = 3

	CTA_MARK = 8

	CTA_PROTOINFO_TCP = 1

	CTA_PROTOINFO_TCP_STATE = 1
)

const (
	IPS_EXPECTED = 1 << iota
	IPS_SEEN_REPLY
	IPS_ASSURED
	IPS_CONFIRMED

	IPS_SRC_NAT
	IPS_DST_NAT
	IPS_SEQ_ADJUST
	IPS_SRC_NAT_DONE

	IPS_DST_NAT_DONE

	IPS_DYING
	IPS_FIXED_TIMEOUT
	IPS_TEMPLATE
	IPS_UNTRACKED
	IPS_HELPER
)

var statusStrings = []string{"IPS_EXPECTED", "IPS_SEEN_REPLY", "IPS_ASSURED", "IPS_CONFIRMED",
	"IPS_SRC_NAT", "IPS_DST_NAT", "IPS_SEQ_ADJUST", "IPS_SRC_NAT_DONE", "IPS_DST_NAT_DONE",
	"IPS_DYING", "IPS_FIXED_TEMPLATE", "IPS_TEMPLATE", "IPS_UNTRACKED", "IPS_HELPER"}


type ConnTuple struct {
	src     net.IP
	dst     net.IP
	srcPort uint16
	dstPort uint16
	proto   uint16
}


type ConnStatus uint32

func (cs ConnStatus) String() string {
	bb := new(bytes.Buffer)
	for i,s := range statusStrings {
		if cs & (1<<uint(i)) != 0 {
			if bb.Len() > 0 {
				bb.WriteString("|")
			}
			bb.WriteString(s)
		}
	}
	return bb.String()
}

type ConnEvent struct {
	orig  ConnTuple
	reply ConnTuple
	id    uint32
	status ConnStatus
	tcpState uint8
}

type NFConntrack struct {
	events       chan *ConnEvent
	pendingError error
	debug        bool
	nls          *nfnetlink.NetlinkSocket
}

func NewNFConntrack() *NFConntrack {
	return &NFConntrack{
		events: make(chan *ConnEvent),
	}
}

func (c *NFConntrack) EnableDebug() {
	if c.nls != nil {
		c.nls.SetFlag(nfnetlink.FlagDebug)
	}
	c.debug = true
}

func (c *NFConntrack) PendingError() error {
	return c.pendingError
}

func (c *NFConntrack) Close() {
	c.nls.Close()
}

func (c *NFConntrack) Open() (<-chan *ConnEvent, error) {
	if err := c.open(); err != nil {
		return nil, err
	}
	go c.receiveEvents()
	return c.events, nil
}

func (c *NFConntrack) open() error {
	nls, err := nfnetlink.NewNetlinkSocket(syscall.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	if err := nls.Subscribe(NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE | NF_NETLINK_CONNTRACK_DESTROY); err != nil {
		nls.Close()
		return err
	}
	c.nls = nls
	if c.debug {
		c.nls.SetFlag(nfnetlink.FlagDebug)
	}
	return nil
}

func (c *NFConntrack) receiveEvents() {
	for m := range c.nls.Receive() {
		if err := c.processPacket(m); err != nil {
			c.pendingError = err
			close(c.events)
			return
		}
	}
	if c.nls.RecvErr() != nil {
		c.pendingError = c.nls.RecvErr()
	}
	close(c.events)
}

func (c *NFConntrack) processPacket(m *nfnetlink.NfNlMessage) error {
	ev := &ConnEvent{}
	extractTuple(m.Attr(CTA_TUPLE_ORIG), &ev.orig)
	extractTuple(m.Attr(CTA_TUPLE_REPLY), &ev.reply)
	m.Attr(CTA_STATUS).ReadFields(&ev.status)
	m.Attr(CTA_ID).ReadFields(&ev.id)
	m.Attr(CTA_PROTOINFO, CTA_PROTOINFO_TCP, CTA_PROTOINFO_TCP_STATE).ReadFields(&ev.tcpState)
	c.events <- ev
	return nil
}

func (e *ConnEvent) String() string {
	return fmt.Sprintf("id: %x orig: %v reply: %v tcp: %v", e.id, e.orig, e.reply, e.tcpState)
}

func (t ConnTuple) String() string {
	return fmt.Sprintf("(%v:%d -> %v:%d)", t.src, t.srcPort, t.dst, t.dstPort)
}

func extractTuple(a *nfnetlink.NLAttr, tuple *ConnTuple) error {
	a.Get(CTA_TUPLE_IP, CTA_IP_V4_SRC).AsIPv4(&tuple.src)
	a.Get(CTA_TUPLE_IP, CTA_IP_V4_DST).AsIPv4(&tuple.dst)
	a.Get(CTA_TUPLE_PROTO, CTA_PROTO_SRC_PORT).ReadFields(&tuple.srcPort)
	a.Get(CTA_TUPLE_PROTO, CTA_PROTO_DST_PORT).ReadFields(&tuple.dstPort)
	a.Get(CTA_TUPLE_PROTO, CTA_PROTO_NUM).ReadFields(&tuple.proto)
	return nil
}

func (c *NFConntrack) MarkConnection(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16, mark uint32) error {
	if c.nls == nil {
		nls, err := nfnetlink.NewNetlinkSocket(syscall.NETLINK_NETFILTER)
		if err != nil {
			return err
		}
		c.nls = nls
	}

	if c.debug {
		c.nls.SetFlag(nfnetlink.FlagDebug)
	}

	err := c.ctNewRequest(srcip, srcport, dstip, dstport, mark).Send()
	return err
}

// This code is pure garbage, but miraculously it seems to work for our use case.
func calcNestSize(nterms int) uint16 {
	return uint16((nterms * 8) + 4)
}

func (c *NFConntrack) ctNewRequest(srcip net.IP, srcport uint16, dstip net.IP, dstport uint16, mark uint32) *nfnetlink.NfNlMessage {
	nr := c.ctnlNewRequest(IPCTNL_MSG_CT_NEW)

//	attr := nfnetlink.NewAttrNested(CTA_TUPLE_ORIG, 0x34)
	attr := nfnetlink.NewAttrNested(CTA_TUPLE_ORIG, calcNestSize(6))
	nr.AddAttribute(attr)

//	attr = nfnetlink.NewAttrNested(CTA_TUPLE_IP, 0x14)
	attr = nfnetlink.NewAttrNested(CTA_TUPLE_IP, calcNestSize(2))
	nr.AddAttribute(attr)

	s32 := binary.BigEndian.Uint32(srcip.To4())
	d32 := binary.BigEndian.Uint32(dstip.To4())

	nr.AddAttributeFields(CTA_IP_V4_SRC, uint32(s32))
	nr.AddAttributeFields(CTA_IP_V4_DST, uint32(d32))
	// nest end: 2 ips nested

//	attr = nfnetlink.NewAttrNested(CTA_TUPLE_PROTO, 0x1c)
	attr = nfnetlink.NewAttrNested(CTA_TUPLE_PROTO, calcNestSize(3))
	nr.AddAttribute(attr)

	nr.AddAttributeFields(CTA_PROTO_NUM, uint8(syscall.IPPROTO_TCP))
	nr.AddAttributeFields(CTA_PROTO_SRC_PORT, srcport)
	nr.AddAttributeFields(CTA_PROTO_DST_PORT, dstport)
	// nest end: proto

	// nest end: tuple

	nr.AddAttributeFields(CTA_MARK, mark)
	return nr
}

// ctnlNewRequest creates a new request of the conntrack subsystem type with the given type
func (c *NFConntrack) ctnlNewRequest(mtype uint8) *nfnetlink.NfNlMessage {
	nlm := c.nls.NewNfNlMsg()
	nlm.Type = uint16((NFNL_SUBSYS_CTNETLINK << 8) | uint16(mtype))
	nlm.Flags = syscall.NLM_F_REQUEST|syscall.NLM_F_ACK
	nlm.Family = syscall.AF_INET
	nlm.Version = nfnetlink.NFNETLINK_V0
	nlm.ResID = 0
	return nlm
}
