package com.entgra.snmp;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.transport.TransportMappings;
import oshi.SystemInfo;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class Agent extends BaseAgent {

    private static final String community = "nusFFVsZDbAEGMFauNj3"; //Auth token of the device
    private static final String ipAddress = "127.0.0.1"; //Thingsboard IP address
    private static final int port = 1620; //Thingsboard SNMP port
    private Set<OID> registeredOIDs = new HashSet<>();

    public Agent() {
        super(new File("bootCounterFile.txt"), new File("configFile.txt"),
                new CommandProcessor(new OctetString(MPv3.createLocalEngineID())));
    }

    @Override
    protected void initTransportMappings() {
        transportMappings = new TransportMapping<?>[1];
        Address addr = GenericAddress.parse("127.0.0.1/1630"); //IP and port of this test client
        TransportMapping<? extends Address> tm = TransportMappings.getInstance().createTransportMapping(addr);
        transportMappings[0] = tm;
    }

    public void start() throws IOException {
        init();
        addShutdownHook();
        getServer().addContext(new OctetString("public"));
        finishInit();
        run();
        sendColdStartNotification();
        sendV2Trap();
    }

    private static PDU createTrapPdu() {
        PDU pdu = new PDU();
        pdu.setType(PDU.TRAP);
        pdu.setRequestID(new Integer32(123));
        pdu.add(new VariableBinding(SnmpConstants.coldStart, new OctetString("Started")));
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

            // Create Transport Mapping
            TransportMapping<?> transport = new DefaultUdpTransportMapping();

            // Send the PDU
            Snmp snmp = new Snmp(transport);
            snmp.send(snmpPDU, comtarget);
            System.out.println("Sent Trap to (IP:Port)=> " + ipAddress + ":" + port);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error in Sending Trap to (IP:Port)=> " + ipAddress
                    + ":" + port);
            System.err.println("Exception Message = " + e.getMessage());
        }
    }


    @Override
    protected void registerManagedObjects() {
        getSnmpv2MIB().unregisterMOs(server, new OctetString("public"));
        System.out.println("Updating MIBs...");
        registerManagedObject(new MOScalar(SnmpConstants.sysUpTime, MOAccessImpl.ACCESS_READ_ONLY, new TimeTicks(new SystemInfo().getHardware().getProcessor().getSystemUptime())));
        registerManagedObject(new MOScalar(SnmpConstants.sysName, MOAccessImpl.ACCESS_READ_ONLY, new OctetString(new SystemInfo().getHardware().getComputerSystem().getModel())));

        registeredOIDs.add(SnmpConstants.sysUpTime);
        registeredOIDs.add(SnmpConstants.sysName);
    }

    private void registerManagedObject(MOScalar mo) {
        try {
            server.register(mo, new OctetString("public"));
            System.out.print("Successfully registered ");
            System.out.println(mo.getID());
        } catch (DuplicateRegistrationException e) {
            System.out.print("Failed to register " + e.getMessage());
            System.out.println(mo.getID());
        }
    }

    @Override
    protected void unregisterManagedObjects() {

        for (OID oid : registeredOIDs) {
            ManagedObject mo = server.getManagedObject(oid, null);
            if (mo != null) {
                server.unregister(mo, null);
            }
        }
        registeredOIDs.clear();
    }

    @Override
    protected void addUsmUser(USM usm) {
        // do nothing
    }

    @Override
    protected void addNotificationTargets(SnmpTargetMIB targetMIB, SnmpNotificationMIB notificationMIB) {
        // do nothing
    }

    @Override
    protected void addViews(VacmMIB vacmMIB) {
        vacmMIB.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString("cpublic"), new OctetString("v1v2group"),
                StorageType.nonVolatile);

        vacmMIB.addAccess(new OctetString("v1v2group"), new OctetString("public"), SecurityModel.SECURITY_MODEL_ANY,
                SecurityLevel.NOAUTH_NOPRIV, MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
                new OctetString("fullWriteView"), new OctetString("fullNotifyView"), StorageType.nonVolatile);

        vacmMIB.addViewTreeFamily(new OctetString("fullReadView"), new OID(".1.3"), new OctetString(),
                VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
    }

    @Override
    protected void addCommunities(SnmpCommunityMIB communityMIB) {
        Variable[] com2sec = new Variable[] {
                new OctetString(community),              // community name
                new OctetString("cpublic"),             // security name
                getAgent().getContextEngineID(),        // local engine ID
                new OctetString("public"),              // default context name
                new OctetString(),                      // transport tag
                new Integer32(StorageType.nonVolatile), // storage type
                new Integer32(RowStatus.active)         // row status
        };
        SnmpCommunityMIB.SnmpCommunityEntryRow row = communityMIB.getSnmpCommunityEntry().createRow(
                new OctetString("public2public").toSubIndex(true), com2sec);
        communityMIB.getSnmpCommunityEntry().addRow(row);
    }
}
