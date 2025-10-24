/* Decompiled by Mocha from AlertDialog.class */
/* Originally compiled from AlertDialog.java */

import java.awt.*;

public class AlertDialog extends Dialog
{
    private Button m_bOK;
    private Label m_labErrMsg;
    private Label m_labErrTitle;
    private boolean m_bError;

    public AlertDialog(Frame frame, String string, boolean flag)
    {
        Label label1;
        Label label2;
        super(frame, "Alert", true);
        m_bOK = new Button("OK");
        m_labErrMsg = new Label();
        m_labErrTitle = new Label("Sorry, an Alert occurred. The Alert message is:");
        m_bError = flag;
        GridBagLayout gridBagLayout = new GridBagLayout();
        setLayout(gridBagLayout);
        if (flag)
        {
            label1 = new Label("Error!!");
            label1.setForeground(Color.red);
            label1.setFont(new Font("TimesRoman", 1, 16));
            label2 = new Label("The connection has been disconnected.  Please fix the problem and click on \"Connect\".");
            label2.setFont(new Font("TimesRoman", 1, 9));
        }
        else
        {
            label1 = new Label("Alert");
            label1.setForeground(Color.blue);
            label1.setFont(new Font("TimesRoman", 1, 16));
            label2 = new Label("This is a non-critical alert message");
            label2.setFont(new Font("TimesRoman", 1, 9));
        }
        Label label3 = new Label(string);
        label3.setFont(new Font("Helvetica", 1, 12));
        CUtil.AddGBComponent(label1, this, gridBagLayout, 0, 0, 1, 1, 1.0, 0.0, 0, 10);
        CUtil.AddGBComponent(label3, this, gridBagLayout, 0, 1, 1, 1, 1.0, 0.0, 0, 17);
        CUtil.AddGBComponent(new Label(), this, gridBagLayout, 0, 2, 1, 1, 1.0, 0.0, 0, 17);
        CUtil.AddGBComponent(label2, this, gridBagLayout, 0, 3, 1, 1, 1.0, 0.0, 0, 17);
        CUtil.AddGBComponent(new Label(), this, gridBagLayout, 0, 4, 1, 1, 1.0, 0.0, 0, 17);
        CUtil.AddGBComponent(m_bOK, this, gridBagLayout, 0, 5, 1, 1, 1.0, 0.0, 0, 10);
        pack();
    }

    public boolean action(Event event, Object object)
    {
        if (event.target == m_bOK)
            hide();
        return super.action(event, object);
    }
}
