/* Decompiled by Mocha from MonitorClient.class */
/* Originally compiled from MonitorClient.java */

import java.awt.*;
import [Ljava.lang.String;;
import java.applet.Applet;
import java.net.URL;
import java.util.Date;

public class MonitorClient extends Applet implements Runnable
{
    Thread m_MonitorClient;
    boolean m_fStandAlone;
    private String m_strHost;
    private int m_nPort;
    private final String PARAM_Host = "Host";
    private final String PARAM_Port = "Port";
    private Date m_CurrentDate;
    private int m_nFrequency;
    private boolean m_bConnected;
    private boolean m_bCancel;
    private boolean m_bSpawned;
    public static final String TITLE_STRING = "SysMon-JClient";
    private ClockThread m_thClock;
    private MonitorConnection m_connection;
    private Button m_buCheckNow;
    private Button m_buChangeProperties;
    private Button m_buQuit;
    private Button m_buConnection;
    private Button m_buAbout;
    private Button m_buCancel;
    private Button m_buSpawn;
    private Panel m_pButton;
    private Label m_labHostPort;
    private Label m_labLastChecked;
    private Label m_labNextCheck;
    private Label m_labCurrentStatus;
    private Label m_labCurrentTime;
    private List m_lData;
    private DataGrid m_gridData;
    private MonitorClientFrame m_frParent;

    String GetParameter(String string1, String astring[])
    {
        CUtil.DPrint("TRACE: MonitorClient.GetParameter()");
        if (astring == null)
            return getParameter(string1);
        String string2 = string1 + "=";
        String string3 = null;
        for (int i = 0; i < astring.length; i++)
        {
            if (string2.equalsIgnoreCase(astring[i].substring(0, string2.length())))
            {
                string3 = astring[i].substring(string2.length());
                if (string3.startsWith("\""))
                {
                    string3 = string3.substring(1);
                    if (string3.endsWith("\""))
                        string3 = string3.substring(0, string3.length() - 1);
                }
            }
        }
        return string3;
    }

    void GetParameters(String astring[])
    {
        CUtil.DPrint("TRACE: MonitorClient.GetParameters()");
        String string = GetParameter("Host", astring);
        if (string != null)
            m_strHost = string;
        string = GetParameter("Port", astring);
        if (string != null)
            m_nPort = Integer.parseInt(string);
    }

    public static void main(String astring[])
    {
        MonitorClientFrame monitorClientFrame = new MonitorClientFrame("MonitorClient");
        monitorClientFrame.resize(600, 300);
        MonitorClient monitorClient = new MonitorClient(monitorClientFrame);
        monitorClientFrame.Setup(monitorClient);
        monitorClientFrame.add("Center", monitorClient);
        monitorClient.m_fStandAlone = true;
        monitorClient.GetParameters(astring);
        monitorClient.init();
        monitorClient.start();
        monitorClientFrame.show();
    }

    public MonitorClient()
    {
        m_fStandAlone = false;
        m_strHost = "puck.nether.net";
        m_nPort = 1345;
        m_nFrequency = 15;
        m_bConnected = true;
        m_bCancel = false;
        m_bSpawned = false;
        m_connection = new MonitorConnection(m_strHost, m_nPort, this);
        m_buCheckNow = new Button("Refresh Now");
        m_buChangeProperties = new Button("Change Properties");
        m_buQuit = new Button("Quit");
        m_buConnection = new Button("Disconnect");
        m_buAbout = new Button("About");
        m_buCancel = new Button("Cancel Refresh");
        m_buSpawn = new Button("External Window");
        m_pButton = new Panel();
        m_labHostPort = new Label(SetHostPortLabel());
        m_labLastChecked = new Label(CUtil.ConvertDate(new Date()));
        m_labNextCheck = new Label(CUtil.ConvertDate(new Date()));
        m_labCurrentStatus = new Label("Retreiving Data    ");
        m_labCurrentTime = new Label();
        m_lData = new List();
        m_gridData = new DataGrid();
        CUtil.DPrint("TRACE: MonitorClient Constructor()");
    }

    public MonitorClient(MonitorClientFrame monitorClientFrame)
    {
        m_fStandAlone = false;
        m_strHost = "monitor.hq.cic.net";
        m_nPort = 1345;
        m_nFrequency = 15;
        m_bConnected = true;
        m_bCancel = false;
        m_bSpawned = false;
        m_connection = new MonitorConnection(m_strHost, m_nPort, this);
        m_buCheckNow = new Button("Refresh Now");
        m_buChangeProperties = new Button("Change Properties");
        m_buQuit = new Button("Quit");
        m_buConnection = new Button("Disconnect");
        m_buAbout = new Button("About");
        m_buCancel = new Button("Cancel Refresh");
        m_buSpawn = new Button("External Window");
        m_pButton = new Panel();
        m_labHostPort = new Label(SetHostPortLabel());
        m_labLastChecked = new Label(CUtil.ConvertDate(new Date()));
        m_labNextCheck = new Label(CUtil.ConvertDate(new Date()));
        m_labCurrentStatus = new Label("Retreiving Data    ");
        m_labCurrentTime = new Label();
        m_lData = new List();
        m_gridData = new DataGrid();
        m_frParent = monitorClientFrame;
    }

    public String getAppletInfo()
    {
        CUtil.DPrint("TRACE: MonitorClient.getAppletInfo()");
        return "Name: MonitorClient\r\nAuthor: Alex Tang\r\nModified by: Jared Mauch\r\n";
    }

    public String[][] getParameterInfo()
    {
        CUtil.DPrint("TRACE: MonitorClient.getParameterInfo()");
        String aastring[][] = { { "Host", "String", "Host name where monitor daemon lives" }, { "Port", "int", "Port Number" } };
        return aastring;
    }

    public void init()
    {
        CUtil.DPrint("TRACE: MonitorClient.init()");
        if (!m_fStandAlone && !m_bSpawned)
        {
            GetParameters(null);
            m_strHost = getDocumentBase().getHost();
        }
        m_labHostPort.setText(SetHostPortLabel());
        m_connection.start();
        m_thClock = new ClockThread(this);
        m_thClock.start();
        setBackground(new Color(192, 192, 192));
        GridBagLayout gridBagLayout1 = new GridBagLayout();
        setLayout(gridBagLayout1);
        Label label1 = new Label("SysMon-JClient");
        label1.setFont(new Font("TimesRoman", 3, 16));
        Label label2 = new Label("Version 1.1");
        label2.setFont(new Font("TimesRoman", 2, 14));
        m_pButton.setLayout(new GridLayout(1, 5, 3, 1));
        m_pButton.add(m_buChangeProperties);
        m_pButton.add(m_buCheckNow);
        m_pButton.add(m_buConnection);
        m_pButton.add(m_buCancel);
        m_buCancel.disable();
        if (m_fStandAlone)
            m_pButton.add(m_buQuit);
        else if (!m_bSpawned)
            m_pButton.add(m_buSpawn);
        InfoPanel infoPanel = new InfoPanel();
        GridBagLayout gridBagLayout2 = new GridBagLayout();
        infoPanel.setLayout(gridBagLayout2);
        Font font1 = new Font("Helvetica", 1, 14);
        Font font2 = new Font("Helvetica", 1, 10);
        Font font3 = new Font("Helvetica", 0, 10);
        Label label3 = new Label("Server");
        label3.setFont(font1);
        Label label4 = new Label("Info:");
        label4.setFont(font1);
        Label label5 = new Label("Host/Port: ");
        label5.setFont(font2);
        Label label6 = new Label("Current Time: ");
        label6.setFont(font2);
        Label label7 = new Label("Last Checked: ");
        label7.setFont(font2);
        Label label8 = new Label("Next Check: ");
        label8.setFont(font2);
        Label label9 = new Label("Current Status: ");
        label9.setFont(font2);
        m_labHostPort.setFont(font3);
        m_labCurrentTime.setFont(font3);
        m_labLastChecked.setFont(font3);
        m_labNextCheck.setFont(font3);
        m_labCurrentStatus.setFont(font3);
        CUtil.AddGBComponent(label5, infoPanel, gridBagLayout2, 1, 0, 1, 1, 0.0, 0.0, 0, 16, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_labHostPort, infoPanel, gridBagLayout2, 1, 1, 1, 1, 0.0, 0.0, 1, 18, new Insets(0, 3, 3, 3), 3, 0);
        CUtil.AddGBComponent(label6, infoPanel, gridBagLayout2, 2, 0, 1, 1, 0.0, 0.0, 0, 16, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_labCurrentTime, infoPanel, gridBagLayout2, 2, 1, 1, 1, 0.0, 0.0, 1, 18, new Insets(0, 3, 3, 3), 3, 0);
        CUtil.AddGBComponent(label7, infoPanel, gridBagLayout2, 3, 0, 1, 1, 0.0, 0.0, 0, 16, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_labLastChecked, infoPanel, gridBagLayout2, 3, 1, 1, 1, 0.0, 0.0, 1, 18, new Insets(0, 3, 3, 3), 3, 0);
        CUtil.AddGBComponent(label8, infoPanel, gridBagLayout2, 4, 0, 1, 1, 0.0, 0.0, 0, 16, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_labNextCheck, infoPanel, gridBagLayout2, 4, 1, 1, 1, 0.0, 0.0, 1, 18, new Insets(0, 3, 3, 3), 3, 0);
        CUtil.AddGBComponent(label9, infoPanel, gridBagLayout2, 5, 0, 1, 1, 0.0, 0.0, 0, 16, new Insets(3, 3, 0, 3), 3, 0);
        CUtil.AddGBComponent(m_labCurrentStatus, infoPanel, gridBagLayout2, 5, 1, 1, 1, 0.0, 0.0, 1, 18, new Insets(0, 3, 3, 3), 3, 0);
        CUtil.AddGBComponent(label1, this, gridBagLayout1, 0, 0, 2, 1, 1.0, 0.0, 0, 17);
        CUtil.AddGBComponent(label2, this, gridBagLayout1, 2, 0, 1, 1, 1.0, 0.0, 0, 13);
        CUtil.AddGBComponent(m_gridData, this, gridBagLayout1, 0, 1, 3, 1, 1.0, 1.0, 1, 10);
        CUtil.AddGBComponent(infoPanel, this, gridBagLayout1, 0, 2, 3, 1, 1.0, 0.0, 1, 10);
        CUtil.AddGBComponent(m_pButton, this, gridBagLayout1, 0, 3, 3, 1, 1.0, 0.0, 1, 10);
    }

    public void destroy()
    {
        CUtil.DPrint("TRACE: MonitorClient.destroy()");
    }

    public void start()
    {
        CUtil.DPrint("TRACE: MonitorClient.start()");
        if (m_MonitorClient == null)
        {
            m_MonitorClient = new Thread(this);
            m_MonitorClient.start();
        }
    }

    public void stop()
    {
        CUtil.DPrint("TRACE: MonitorClient.stop()");
        if (m_MonitorClient != null && !m_bSpawned)
        {
            m_connection.stop();
            m_thClock.stop();
            m_MonitorClient.stop();
            m_MonitorClient = null;
        }
    }

    public void run()
    {
        CUtil.DPrint("TRACE: MonitorClient.run()");
        while (true)
        {
            try
            {
                repaint();
                Thread.sleep(50);
            }
            catch (InterruptedException e)
            {
                stop();
            }
        }
    }

    public boolean action(Event event, Object object)
    {
        if (event.target == m_buCheckNow)
            m_connection.ForceGetData();
        else if (event.target == m_buChangeProperties)
        {
            for (Container container = getParent(); container != null; container = container.getParent())
            {
                if (container instanceof Frame)
                {
                    UpdatePropertiesDialog updatePropertiesDialog = new UpdatePropertiesDialog((Frame)container, m_nFrequency, this);
                    updatePropertiesDialog.show();
                }
            }
        }
        else if (event.target == m_buQuit)
        {
            stop();
            hide();
            if (m_frParent != null)
                m_frParent.hide();
            if (m_fStandAlone)
                System.exit(0);
        }
        else if (event.target == m_buConnection)
        {
            if (m_bConnected)
                Disconnect();
            else
                Connect();
        }
        else if (event.target == m_buCancel)
        {
            CUtil.DPrint("TRACE: MonitorClient.action(): Cancel Pressed!");
            m_bCancel = true;
        }
        else if (event.target == m_buSpawn)
        {
            m_bSpawned = true;
            m_frParent = new MonitorClientFrame("SysMon-JClient");
            m_frParent.add("Center", this);
            m_frParent.resize(600, 300);
            m_pButton.remove(m_buSpawn);
            m_frParent.show();
        }
        return super.action(event, object);
    }

    private void Disconnect()
    {
        m_bConnected = false;
        m_buCheckNow.disable();
        m_labNextCheck.setText("None: Disconnected");
        m_labCurrentStatus.setText("Disconnected");
        m_buConnection.setLabel("Connect");
        m_buConnection.enable();
    }

    private void Connect()
    {
        m_bConnected = true;
        m_buCheckNow.enable();
        m_connection.ForceGetData();
        m_buConnection.setLabel("Disconnect");
    }

    public boolean GetConnected()
    {
        return m_bConnected;
    }

    public boolean handleEvent(Event event)
    {
        if (event.id == 201)
        {
            stop();
            if (m_fStandAlone)
                System.exit(0);
        }
        return super.handleEvent(event);
    }

    public void UpdateData(AlertRecord aalertRecord[])
    {
        m_gridData.UpdateTable(aalertRecord);
    }

    public void SetFrequency(int i)
    {
        m_nFrequency = i;
    }

    public int GetFrequency()
    {
        return m_nFrequency;
    }

    public void UpdateStatus(boolean flag)
    {
        CUtil.DPrint("TRACE: MonitorClient.UpdateStatus(), arg: " + flag);
        if (flag)
        {
            m_labCurrentStatus.setText("Getting Data");
            m_labCurrentStatus.setForeground(Color.blue);
            m_labNextCheck.setText("Checking...");
            CUtil.DPrint("    About to enable the Cancel Button.");
            m_buCancel.enable();
            m_buCheckNow.disable();
            m_buConnection.disable();
            return;
        }
        m_labCurrentStatus.setText("Sleeping");
        m_labCurrentStatus.setForeground(Color.black);
        m_buCancel.disable();
        m_buCheckNow.enable();
        m_buConnection.enable();
    }

    public void UpdateStatusString(String string)
    {
        m_labCurrentStatus.setText(string);
    }

    public void UpdateCheckTimes()
    {
        Date date1 = new Date();
        CUtil.DPrint("Timezone offset for d: " + date1.getTimezoneOffset());
        long i = Date.UTC(date1.getYear(), date1.getMonth(), date1.getDate(), date1.getHours(), date1.getMinutes(), date1.getSeconds());
        long j = i + m_nFrequency * 1000 + date1.getTimezoneOffset() * 60000;
        Date date2 = new Date(j);
        m_labLastChecked.setText(CUtil.ConvertDate(date1));
        m_labNextCheck.setText(CUtil.ConvertDate(date2));
    }

    public void UpdateLastCheckTime()
    {
        Date date = new Date();
        CUtil.DPrint("Timezone offset for d: " + date.getTimezoneOffset());
        m_labLastChecked.setText(CUtil.ConvertDate(date));
    }

    public void UpdateNextCheckTime()
    {
        Date date1 = new Date();
        CUtil.DPrint("Timezone offset for d: " + date1.getTimezoneOffset());
        long i = Date.UTC(date1.getYear(), date1.getMonth(), date1.getDate(), date1.getHours(), date1.getMinutes(), date1.getSeconds());
        long j = i + m_nFrequency * 1000 + date1.getTimezoneOffset() * 60000;
        Date date2 = new Date(j);
        m_labNextCheck.setText(CUtil.ConvertDate(date2));
    }

    public void UpdateClock()
    {
        String string = CUtil.ConvertDate(new Date());
        m_labCurrentTime.setText(string);
    }

    public boolean GetStandalone()
    {
        return m_fStandAlone;
    }

    public String SetHostPortLabel()
    {
        return m_strHost + "/" + m_nPort;
    }

    public void ForceGetData()
    {
        m_connection.ForceGetData();
    }

    public String GetHostname()
    {
        return m_strHost;
    }

    public int GetPort()
    {
        return m_nPort;
    }

    public void SetHostInfo(String string, int i)
    {
        m_strHost = string;
        m_nPort = i;
        m_labHostPort.setText(SetHostPortLabel());
    }

    public void Error(String string)
    {
        CUtil.DPrint("TRACE: MonitorClient.Error");
        Disconnect();
        m_labCurrentStatus.setText("Error!");
        m_labCurrentStatus.setForeground(Color.red);
        for (Container container = getParent(); container != null; container = container.getParent())
        {
            if (container instanceof Frame)
            {
                AlertDialog alertDialog = new AlertDialog((Frame)container, string, 1);
                alertDialog.show();
            }
        }
    }

    public boolean GetCancel()
    {
        return m_bCancel;
    }

    public void SetCancel(boolean flag)
    {
        m_bCancel = flag;
    }
}
