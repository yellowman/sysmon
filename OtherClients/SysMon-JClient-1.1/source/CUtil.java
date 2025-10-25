/* Decompiled by Mocha from CUtil.class */
/* Originally compiled from CUtil.java */

import java.awt.*;
import java.io.PrintStream;
import java.util.Date;

public class CUtil
{
    public static final boolean c_bDebug = false;

    public static void AddGBComponent(Component component, Container container, GridBagLayout gridBagLayout, int i1, int j1, int k1, int i2, double d1, double d2, int j2, int k2)
    {
        AddGBComponent(component, container, gridBagLayout, i1, j1, k1, i2, d1, d2, j2, k2, new Insets(3, 3, 3, 3), 0, 0);
    }

    public static void AddGBComponent(Component component, Container container, GridBagLayout gridBagLayout, int i1, int j1, int k1, int i2, double d1, double d2, int j2, int k2, Insets insets, int i3, int j3)
    {
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = i1;
        gridBagConstraints.gridy = j1;
        gridBagConstraints.gridwidth = k1;
        gridBagConstraints.gridheight = i2;
        gridBagConstraints.weightx = d1;
        gridBagConstraints.weighty = d2;
        gridBagConstraints.anchor = k2;
        gridBagConstraints.ipadx = 3;
        gridBagConstraints.ipady = 3;
        gridBagConstraints.insets = insets;
        gridBagConstraints.ipadx = i3;
        gridBagConstraints.ipady = j3;
        gridBagConstraints.fill = j2;
        gridBagLayout.setConstraints(component, gridBagConstraints);
        container.add(component);
    }

    public static void DPrint(String string)
    {
    }

    public static void DPrintln(String string)
    {
    }

    public static String ConvertDate(Date date)
    {
        String string1 = String.valueOf(date.getMonth() + 1);
        String string2 = (date.getHours() < 10) ? ("0" + String.valueOf(date.getHours())) : String.valueOf(date.getHours());
        String string3 = (date.getMinutes() < 10) ? ("0" + String.valueOf(date.getMinutes())) : String.valueOf(date.getMinutes());
        String string4 = (date.getSeconds() < 10) ? ("0" + String.valueOf(date.getSeconds())) : String.valueOf(date.getSeconds());
        String string5 = new String(string1 + "/" + date.getDate() + "/" + date.getYear() + ", " + string2 + ":" + string3 + ":" + string4);
        return string5;
    }

    public CUtil()
    {
    }
}
