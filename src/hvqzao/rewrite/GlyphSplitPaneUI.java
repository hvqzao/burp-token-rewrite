package hvqzao.rewrite;

import java.awt.Color;
import java.awt.Graphics;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;

class GlyphSplitPaneUI extends BasicSplitPaneUI {

    private final Color ORANGE_COLOR = new Color(255, 102, 51);
    private final Color backgroundColor;

    public GlyphSplitPaneUI(Color backgroundColor) {
        this.backgroundColor = backgroundColor;
    }
    
    @Override
    public BasicSplitPaneDivider createDefaultDivider() {
        return new BasicSplitPaneDivider(this) {

            @Override
            public void paint(Graphics g) {
                g.setColor(backgroundColor);
                g.fillRect(0, 0, getSize().width, getSize().height);
                int mid = getSize().height / 2;
                g.setColor(ORANGE_COLOR);
                int min = 4;
                int max = 9;
                for (int i = min; i <= max; i++) {
                    g.drawLine(i, mid - max + i, i, mid + max - i);
                }
                super.paint(g);
            }
        };
    }
}
