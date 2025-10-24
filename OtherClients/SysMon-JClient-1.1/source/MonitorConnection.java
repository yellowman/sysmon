/* Decompiled by Mocha from MonitorConnection.class */
/* Originally compiled from MonitorConnection.java */

import java.io.*;
import java.net.Socket;
import java.util.Date;
import java.util.Vector;

public class MonitorConnection extends Thread
{
    private String m_strHost;
    private int m_nPort;
    private MonitorClient m_client;
    private boolean m_bInterrupted;

    public void Interrupt()
    {
        m_bInterrupted = true;
    }

    public synchronized void run()
    {
        Object object;
        AlertRecord aalertRecord[];
        Exception e;
        while (true)
        {
            if (m_client.GetConnected())
            {
                object = new Date();
                CUtil.DPrint("Time: " + object);
                m_client.UpdateStatus(true);
                try
                {
                    aalertRecord = GetData();
                    m_client.UpdateNextCheckTime();
                    if (aalertRecord != null)
                    {
                        m_client.UpdateStatus(false);
                        m_client.UpdateLastCheckTime();
                        m_client.UpdateData(aalertRecord);
                    }
                    else
                    {
                        m_client.SetCancel(false);
                        m_client.UpdateStatus(false);
                    }
                }
                catch ()
                {
                    m_client.Error(e.toString());
                }
            }
            try
            {
                wait((long)(m_client.GetFrequency() * 1000));
            }
            catch ()
            {
                m_client.Error(object.toString());
            }
        }
    }

    public MonitorConnection(String string, int i, MonitorClient monitorClient)
    {
        super("Monitor Connection Thread ");
        m_strHost = new String();
        m_bInterrupted = false;
        m_strHost = string;
        m_nPort = i;
        m_client = monitorClient;
    }

    public synchronized void ForceGetData()
    {
        CUtil.DPrint("Got FORCE DATA!");
        notify();
    }

    public synchronized AlertRecord[] GetData()
        throws Exception
    {
        int i;
        Vector vector = new Vector();
        try
        {
            m_client.UpdateStatusString("Connecting");
            local = new Socket(m_client.GetHostname(), m_client.GetPort());
            DataInputStream dataInputStream = new DataInputStream(local.getInputStream());
            PrintStream printStream = new PrintStream(local.getOutputStream());
            m_client.UpdateStatusString("Negotiating");
            String string = GetLine(dataInputStream);
            string.substring(0, 3);
            if (!string.substring(0, 3).equals("111"))
            {
                CUtil.DPrint("ERROR connecting...");
                throw new Exception("Server didn't send correct greeting: " + string);
            }
            m_client.UpdateStatusString("Requesting Info");
            printStream.println("STAT");
            m_client.UpdateStatusString("Receiving Info");
            string = GetLine(dataInputStream);
            for (string = string.trim(); !string.substring(0, 3).equals("333"); string = string.trim())
            {
                vector.addElement(string);
                string = GetLine(dataInputStream);
            }
            printStream.println("QUIT");
            m_client.UpdateStatusString("Closing Connection");
            local.close();
            local = new AlertRecord[vector.size()];
            i = 0;
        }
        catch ()
        {
            CUtil.DPrint(local.toString());
            throw new Exception("IO Exception: " + local.toString());
        }
        catch ()
        {
            CUtil.DPrint("Caught Interrupted Exception.: " + local.toString());
            return null;
        }
        for (; i < vector.size(); i++)
            local[i] = new AlertRecord((String)vector.elementAt(i));
        return local;
    }

    private String GetLine(DataInputStream dataInputStream)
        throws InterruptedException, IOException
    {
        CUtil.DPrint("TRACE: MonitorConnection.GetLine()");
        while (true)
        {
            if (m_client.GetCancel())
                throw new InterruptedException("Cancel Pressed.");
            CUtil.DPrint("    GetLine(): Getting Cancel: " + m_client.GetCancel());
            if (dataInputStream.available() > 0)
            {
                String string = dataInputStream.readLine();
                return string;
            }
            wait(1000);
        }
    }
}
