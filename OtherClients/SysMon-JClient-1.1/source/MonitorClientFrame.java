/* Decompiled by Mocha from MonitorClientFrame.class */
/* Originally compiled from MonitorClientFrame.java */

import java.awt.*;

class MonitorClientFrame extends Frame
{
    private MonitorClient m_client;

    public MonitorClientFrame(String string)
    {
        super(string);
    }

    public void Setup(MonitorClient monitorClient)
    {
        m_client = monitorClient;
    }

    public boolean handleEvent(Event event)
    {
        switch (event.id)
        {
        case 201:
            dispose();
            break;

        default:
            return super.handleEvent(event);
        }
        if (m_client.GetStandalone())
            System.exit(0);
        return true;
    }
}
