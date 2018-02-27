// Token Rewrite Burp Extension, (c) 2016-2018 Marcin Woloszyn (@hvqzao), Released under MIT license
// Contributors: Eduardo Garcia
//
package hvqzao.rewrite;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import java.awt.Component;
import java.awt.Dimension;
import java.io.PrintWriter;
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class TokenRewriteExtension implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static ImageIcon iconHelp;
    private static ImageIcon iconDefaults;
    private static Dimension iconDimension;
    private static PrintWriter stderr;
    private JScrollPane optionsTab;
    private TokenRewriteOptions optionsPane;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        TokenRewriteExtension.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        // stderr
        stderr = new PrintWriter(callbacks.getStderr(), true);
        // set extension name
        callbacks.setExtensionName("Token Rewrite");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            // images
            iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/rewrite/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/rewrite/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            iconDimension = new Dimension(24, 24);
            // extension tab
            optionsPane = new TokenRewriteOptions();
            //
            optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            optionsTab.setFocusable(false);
            //optionsPane.requestFocus();
            //
            optionsPane.start();
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(TokenRewriteExtension.this);
            //
            //int row = token.size();
            //token.add(new TokenEntry());
            //token.add(new TokenEntry());
            //token.add(new TokenEntry());
            //tokenTableModel.fireTableRowsInserted(row, row);
            //
            //callbacks.printOutput("Loaded.");
        });
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static ImageIcon getIconHelp() {
        return iconHelp;
    }

    public static ImageIcon getIconDefaults() {
        return iconDefaults;
    }

    public static Dimension getIconDimension() {
        return iconDimension;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        return "Rewrite";
    }

    @Override
    public Component getUiComponent() {
        return optionsTab;
    }

}
