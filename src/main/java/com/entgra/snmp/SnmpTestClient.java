package com.entgra.snmp;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Vector;

import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;
import oshi.SystemInfo;

public class SnmpTestClient implements CommandResponder {

    private static final String community = "nusFFVsZDbAEGMFauNj3";      //SET THIS
    private static final String ipAddress = "127.0.0.1";     //SET THIS (this is the destination address)
    private static final int port = 1620;

    private Snmp snmp = null;

    public static void main(String[] args) {
        new SnmpTestClient().run();
    }

    private void run() {
        try {
            init();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void init() throws IOException {
        ThreadPool threadPool = ThreadPool.create("Trap", 10);
        MultiThreadedMessageDispatcher dispatcher = new MultiThreadedMessageDispatcher(threadPool,
                new MessageDispatcherImpl());

        //TRANSPORT
        Address listenAddress = GenericAddress.parse(System.getProperty(
                "snmp4j.listenAddress", "udp:192.168.8.150/1630"));  //SET THIS
        TransportMapping<?> transport;
        if (listenAddress instanceof UdpAddress) {
            transport = new DefaultUdpTransportMapping(
                    (UdpAddress) listenAddress);
        } else {
            transport = new DefaultTcpTransportMapping(
                    (TcpAddress) listenAddress);
        }

        //V3 SECURITY
        USM usm = new USM(
                SecurityProtocols.getInstance().addDefaultProtocols(),
                new OctetString(MPv3.createLocalEngineID()), 0);

        SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
        SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        usm.setEngineDiscoveryEnabled(true);

        SecurityModels.getInstance().addSecurityModel(usm);

        snmp = new Snmp(dispatcher, transport);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        snmp.listen();
        snmp.addCommandResponder(this);
        sendV2Trap();
    }

    private static PDU createTrapPdu() {
        PDU pdu = new PDU();
        pdu.setType(PDU.TRAP);
        pdu.setRequestID(new Integer32(123));
        pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(new SystemInfo().getHardware().getProcessor().getSystemUptime())));
        return pdu;
    }

    private void sendV2Trap() {
        try {
            // create v1/v2 PDU
            PDU snmpPDU = createTrapPdu();

            // Create Target
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString(community));
            comtarget.setVersion(SnmpConstants.version2c);
            comtarget.setAddress(new UdpAddress(ipAddress + "/" + port));
            comtarget.setRetries(2);
            comtarget.setTimeout(5000);

            // Send the PDU
            snmp.send(snmpPDU, comtarget);
            System.out.println("Sent Trap to (IP:Port)=> " + ipAddress + ":" + port);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error in Sending Trap to (IP:Port)=> " + ipAddress
                    + ":" + port);
            System.err.println("Exception Message = " + e.getMessage());
        }
    }

    public void processPdu(CommandResponderEvent crEvent) {
        PDU pdu = crEvent.getPDU();
        System.out.println("");
        if (pdu.getType() == PDU.V1TRAP) {
            PDUv1 pduV1 = (PDUv1) pdu;
            System.out.println("===== NEW SNMP 1 TRAP RECEIVED ====");
            System.out.println("agentAddr " + pduV1.getAgentAddress().toString());
            System.out.println("enterprise " + pduV1.getEnterprise().toString());
            System.out.println("timeStamp" + String.valueOf(pduV1.getTimestamp()));
            System.out.println("genericTrap"+ String.valueOf(pduV1.getGenericTrap()));
            System.out.println("specificTrap " + String.valueOf(pduV1.getSpecificTrap()));
            System.out.println("snmpVersion " + String.valueOf(PDU.V1TRAP));
            System.out.println("communityString " + new String(crEvent.getSecurityName()));
        } else if (pdu.getType() == PDU.TRAP) {
            System.out.println("===== NEW SNMP 2/3 TRAP RECEIVED ====");
            System.out.println("errorStatus " + String.valueOf(pdu.getErrorStatus()));
            System.out.println("errorIndex "+ String.valueOf(pdu.getErrorIndex()));
            System.out.println("requestID " +String.valueOf(pdu.getRequestID()));
            System.out.println("snmpVersion " + String.valueOf(PDU.TRAP));
        } else if (pdu.getType() == PDU.GET) {
            System.out.println("===== NEW SNMP GET RECEIVED ====");
        }
        System.out.println("communityString " + new String(crEvent.getSecurityName()));


        Vector<? extends VariableBinding> varBinds = pdu.getVariableBindings();
        if (varBinds != null && !varBinds.isEmpty()) {
            Iterator<? extends VariableBinding> varIter = varBinds.iterator();

            System.out.println("------");
            while (varIter.hasNext()) {
                VariableBinding vb = varIter.next();

                String syntaxstr = vb.getVariable().getSyntaxString();
                int syntax = vb.getVariable().getSyntax();
                System.out.println( "OID: " + vb.getOid());
                System.out.println("Value: " +vb.getVariable());
                System.out.println("syntaxstring: " + syntaxstr );
                System.out.println("syntax: " + syntax);
                System.out.println("------");

            }
        }
        System.out.println("==== END ===");
        System.out.println("");
    }
}
