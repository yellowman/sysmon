/* Decompiled by Mocha from DataGrid.class */
/* Originally compiled from DataGrid.java */

import java.awt.*;
import mlsoft.mct.*;

public class DataGrid extends Panel
{
    MlGrid m_gridData;
    MlResources m_resData;

    public DataGrid()
    {
        m_gridData = new MlGrid();
        m_gridData.setValue("layoutFrozen", true);
        MlResources mlResources = new MlResources();
        mlResources.add("columns", 7);
        mlResources.add("horizontalSizePolicy", "SIZE_FIXED");
        mlResources.add("selectionPolicy", "SELECT_NONE");
        mlResources.add("leftFixedCount", 1);
        mlResources.add("rows", 0);
        mlResources.add("simpleWidths", "30c 10c 5c 30c 7c 8c 30c");
        mlResources.add("visibleRows", "10");
        mlResources.add("allowColumnResize", true);
        mlResources.add("topFixedMargin", 3);
        m_gridData.setValues(mlResources);
        mlResources.clear();
        mlResources.add("cellDefaults", true);
        mlResources.add("cellFont", new Font("Helvetica", 1, 12));
        mlResources.add("cellBackground", "#FFFF00");
        mlResources.add("cellForeground", "#000080");
        mlResources.add("cellTopBorderType", "BORDER_NONE");
        mlResources.add("cellBottomBorderColor", "#000000");
        mlResources.add("cellAlignment", "ALIGNMENT_CENTER");
        m_gridData.setValues(mlResources);
        m_gridData.addRows(0, 0, 1);
        mlResources.clear();
        mlResources.add("simpleHeadings", "HostName|Serv.Type|Port|Last Check Status|Count|Notified|Time Failed");
        m_gridData.setValues(mlResources);
        mlResources.clear();
        mlResources.add("cellDefaults", true);
        mlResources.add("cellAlignment", "ALIGNMENT_CENTER");
        mlResources.add("cellFont", new Font("Helvetica", 0, 12));
        mlResources.add("cellLeftBorderType", "BORDER_NONE");
        mlResources.add("cellRightBorderType", "BORDER_NONE");
        mlResources.add("cellTopBorderType", "BORDER_NONE");
        mlResources.add("cellBottomBorderColor", "#000000");
        mlResources.add("cellBackground", "#FFFFFF");
        mlResources.add("cellForeground", "#000000");
        m_gridData.setValues(mlResources);
        mlResources.clear();
        mlResources.add("cellDefaults", true);
        mlResources.add("column", 0);
        mlResources.add("cellAlignment", "ALIGNMENT_LEFT");
        mlResources.add("cellFont", new Font("Helvetica", 1, 12));
        m_gridData.setValues(mlResources);
        mlResources.clear();
        mlResources.add("cellDefaults", true);
        mlResources.add("column", 3);
        mlResources.add("cellAlignment", "ALIGNMENT_LEFT");
        m_gridData.setValues(mlResources);
        m_gridData.setValue("layoutFrozen", false);
        GridBagLayout gridBagLayout = new GridBagLayout();
        setLayout(gridBagLayout);
        CUtil.AddGBComponent(m_gridData, this, gridBagLayout, 0, 0, 1, 1, 1.0, 1.0, 1, 10, new Insets(0, 0, 0, 0), 0, 0);
    }

    public void UpdateTable(AlertRecord aalertRecord[])
    {
        CUtil.DPrint("TRACE: DataGrid.UpdateTable()");
        int i = aalertRecord.length;
        ((Integer)m_gridData.getValue("rows")).intValue();
        MlResources mlResources = new MlResources();
        mlResources.add("rows", i);
        m_gridData.setValues(mlResources);
        for (int j = 0; j < i; j++)
        {
            m_gridData.setStrings(j, aalertRecord[j].toGridString());
            CUtil.DPrint("Adding Row: " + j + ": " + aalertRecord[j].toGridString());
        }
    }
}
