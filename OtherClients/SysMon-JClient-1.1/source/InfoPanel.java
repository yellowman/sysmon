/* Decompiled by Mocha from InfoPanel.class */
/* Originally compiled from InfoPanel.java */

import java.awt.*;

public class InfoPanel extends Panel
{
    public InfoPanel()
    {
    }

    public void paint(Graphics g)
    {
        g.setColor(Color.black);
        g.drawRect(0, 0, size().width - 1, size().height - 1);
    }
}
