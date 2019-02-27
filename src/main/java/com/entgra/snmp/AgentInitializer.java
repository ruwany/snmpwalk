package com.entgra.snmp;

import java.io.IOException;

public class AgentInitializer {
    public static void main(String[] args){
        Agent agent = new Agent();
        try {
            agent.start();
            while(true) {
                System.out.println("Agent running...");
                Thread.sleep(5000);
                agent.registerManagedObjects();
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
