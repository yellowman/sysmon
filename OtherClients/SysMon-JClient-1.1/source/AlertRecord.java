/* Decompiled by Mocha from AlertRecord.class */
/* Originally compiled from AlertRecord.java */

import java.util.Date;
import java.util.StringTokenizer;

public class AlertRecord
{
    private String m_strHost;
    private int m_nServiceType;
    private int m_nPort;
    private int m_nLastCheckStatus;
    private int m_nDownCount;
    private boolean m_bNotified;
    private Date m_dateTimeFailed;

    public AlertRecord()
    {
    }

    public AlertRecord(String string)
    {
        StringTokenizer stringTokenizer = new StringTokenizer(string, ":");
        if (stringTokenizer.countTokens() != 7)
            CUtil.DPrint("Error, strAlert: " + string + " doesn't have 7 tokens");
        m_strHost = stringTokenizer.nextToken();
        m_nServiceType = Integer.parseInt(stringTokenizer.nextToken());
        m_nPort = Integer.parseInt(stringTokenizer.nextToken());
        m_nLastCheckStatus = Integer.parseInt(stringTokenizer.nextToken());
        m_nDownCount = Integer.parseInt(stringTokenizer.nextToken());
        m_bNotified = Integer.parseInt(stringTokenizer.nextToken()) == 1;
        m_dateTimeFailed = new Date(Long.parseLong(stringTokenizer.nextToken()) * 1000);
    }

    public String GetHostName()
    {
        return m_strHost;
    }

    public int GetServiceType()
    {
        return m_nServiceType;
    }

    public String GetServiceTypeString()
    {
        switch (m_nServiceType)
        {
	case 0:
		return "OK";
        case 1:
		return "TCP";
        case 2:
		return "UDP";
        case 3:
		return "PING";
        case 4:
		return "SNMP";
        case 5:
		return "NNTP";
        case 6:
		return "SMTP";
        case 7:
		return "IMAP";
        case 8:
		return "POP3";
	case 9:
		return "X500";
	case 10:
		return "POP2";
	case 11:
		return "BOOTP";
	case 12:
		return "DNS";
	case 13:
		return "WWW";
	case 14:
		return "RADIUS";
	case 15:
		return "HTTPS";
	case 16:
		return "SYSMON";
	case 17:
		return "SSH";
	case 18:
		return "IRCd";
	case 19:
		return "PING-latency";
	case 20:
		return "PINGv6";
	case 21:
		return "UDP_RTT";
        default:
            return "UKNOWN";
        }
    }

    public String GetPortString()
    {
        if (m_nPort > 0)
            return String.valueOf(m_nPort);
        else
            return " ";
    }

    public int GetPort()
    {
        return m_nPort;
    }

    public int GetLastCheckStatus()
    {
        return m_nLastCheckStatus;
    }

    public String GetLastCheckStatusString()
    {
        switch (m_nLastCheckStatus)
        {
        case 0:
            return "ERROR, Host is fine";

        case 1:
            return "Connection Refused";

        case 2:
            return "Network is Unreachable";

        case 3:
            return "Host is Down or Host Not Respoding";

        case 4:
            return "Connection Timed Out";

        case 5:
            return "No DNS for host";

        case 6:
            return "Host is Unpingable";

        case 7:
            return "Server Throttled";

        case 8:
            return "Server Refused Authorization";

        case 9:
            return "No Server Response";

	case 10:
		return "In Progress";
	case 11:
		return "Failed Authentication";
	case 12:
		return "Bad response";
	case 13:
		return "Wedged";
	case 14:
		return "Killed";
	case 15:
		return "Host Unreachable";
	case 16:
		return "RTT High";
	case 17:
		return "Host Rebooted";
	case 18:
		return "SNMP - Too High";
	case 19:
		return "SNMP - Too Low";
	case 20:
		return "SNMP - Out of Range";
	case 21:
		return "SNMP - Not Exact";
	case 22:
		return "SNMP - Rate too High";
        default:
            return "Unknown Error";
        }
    }

    public String GetDownCountString()
    {
        return String.valueOf(m_nDownCount);
    }

    public int GetDownCount()
    {
        return m_nDownCount;
    }

    public boolean GetNotified()
    {
        return m_bNotified;
    }

    public String GetNotifiedString()
    {
        if (m_bNotified)
            return "Yes";
        else
            return "No";
    }

    public String GetTimeServiceFailedString()
    {
        return m_dateTimeFailed.toString();
    }

    public Date GetTimeServiceFailed()
    {
        return m_dateTimeFailed;
    }

    public String toString()
    {
        return "ALERT: " + m_strHost + ", " + "Service Type: " + GetServiceTypeString() + ", " + "Port: " + m_nPort + ", " + "Last Check Status: " + GetLastCheckStatusString() + ", " + "Down Count: " + m_nDownCount + ", " + "Notified: " + m_bNotified + ", " + "Time Failed: " + m_dateTimeFailed + ". ";
    }

    public String toGridString()
    {
        return m_strHost + "|" + GetServiceTypeString() + "|" + GetPortString() + "|" + GetLastCheckStatusString() + "|" + m_nDownCount + "|" + GetNotifiedString() + "|" + m_dateTimeFailed;
    }
}
