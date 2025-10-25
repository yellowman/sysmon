/* Decompiled by Mocha from UpdatePropertiesDialog.class */
/* Originally compiled from UpdatePropertiesDialog.java */

import java.awt.*;

public class UpdatePropertiesDialog extends Dialog
{
    private TextField m_tfSec;
    private TextField m_tfHostname;
    private TextField m_tfPort;
    private Button m_bOK;
    MonitorClient m_client;

    public UpdatePropertiesDialog(Frame frame, int i, MonitorClient monitorClient)
    {
        super(frame, "Update Properties", true);
        m_tfSec = new TextField(4);
        m_tfHostname = new TextField(20);
        m_tfPort = new TextField(4);
        m_bOK = new Button("OK");
        m_client = monitorClient;
        m_tfSec.setText(String.valueOf(i));
        m_tfHostname.setText(monitorClient.GetHostname());
        m_tfPort.setText(String.valueOf(monitorClient.GetPort()));
        m_tfHostname.setEditable(monitorClient.GetStandalone());
        Panel panel1 = new Panel();
        GridBagLayout gridBagLayout1 = new GridBagLayout();
        panel1.setLayout(gridBagLayout1);
        CUtil.AddGBComponent(new Label("Seconds between data refreshes (Must be 10 or more): "), panel1, gridBagLayout1, 0, 0, 1, 1, 0.0, 0.0, 0, 17, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_tfSec, panel1, gridBagLayout1, 1, 0, 1, 1, 1.0, 0.0, 0, 17, new Insets(3, 3, 0, 3), 3, 0);
        Panel panel2 = new Panel();
        panel2.setLayout(new GridLayout(1, 2, 2, 3));
        panel2.add(new Button("Cancel"));
        panel2.add(m_bOK);
        GridBagLayout gridBagLayout2 = new GridBagLayout();
        setLayout(gridBagLayout2);
        CUtil.AddGBComponent(new Label("SysMon server hostname: "), this, gridBagLayout2, 0, 0, 1, 1, 1.0, 0.0, 2, 17, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_tfHostname, this, gridBagLayout2, 0, 1, 1, 1, 1.0, 0.0, 2, 17, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(new Label("Port Number: "), this, gridBagLayout2, 1, 0, 1, 1, 0.0, 0.0, 0, 17, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_tfPort, this, gridBagLayout2, 1, 1, 1, 1, 0.0, 0.0, 0, 17, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(panel1, this, gridBagLayout2, 0, 3, 2, 1, 1.0, 1.0, 0, 10, new Insets(3, 3, 3, 3), 0, 5);
        CUtil.AddGBComponent(panel2, this, gridBagLayout2, 0, 5, 2, 1, 1.0, 1.0, 0, 10);
        pack();
    }

    public boolean action(Event event, Object object)
    {
        if (object.equals("OK") || event.target == m_tfSec)
        {
            int i = Integer.parseInt(m_tfSec.getText());
            hide();
            if (i < 3)
            {
                String string = new String("The number of seconds (" + i + ") was too low, so it has been re-set to 10.");
                i = 3;
                for (Container container = getParent(); container != null; container = container.getParent())
                {
                    if (container instanceof Frame)
                    {
                        AlertDialog alertDialog = new AlertDialog((Frame)container, string, 0);
                        alertDialog.show();
                    }
                }
            }
            m_client.SetFrequency(i);
            m_client.SetHostInfo(m_tfHostname.getText(), Integer.parseInt(m_tfPort.getText()));
            m_client.ForceGetData();
        }
        else if (object.equals("Cancel"))
            hide();
        return super.action(event, object);
    }

    public boolean handleEvent(Event event)
    {
        if (event.id == 402)
        {
            if (m_tfHostname.getText().length() > 0 && m_tfPort.getText().length() > 0 && m_tfSec.getText().length() > 0)
                m_bOK.enable();
            else
                m_bOK.disable();
        }
        return super.handleEvent(event);
    }
}
