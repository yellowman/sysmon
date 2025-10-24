/* Decompiled by Mocha from ClockThread.class */
/* Originally compiled from ClockThread.java */

import java.io.PrintStream;

public class ClockThread extends Thread
{
    MonitorClient m_client;

    public ClockThread(MonitorClient monitorClient)
    {
        super("Clock Thread");
        m_client = monitorClient;
    }

    public synchronized void run()
    {
        InterruptedException e;
        while (true)
        {
            m_client.UpdateClock();
            try
            {
                wait(1000);
            }
            catch ()
            {
                System.out.println(e);
            }
        }
    }
}
