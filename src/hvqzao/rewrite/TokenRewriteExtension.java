// Token Rewrite Burp Extension, (c) 2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.rewrite;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class TokenRewriteExtension implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    private JFrame burpFrame;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        TokenRewriteExtension.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        // set extension name
        callbacks.setExtensionName("Token Rewrite");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            // images
            ImageIcon iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/rewrite/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            ImageIcon iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/rewrite/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            Dimension iconDimension = new Dimension(24, 24);
            // extension tab
            TokenRewriteOptions optionsPane = new TokenRewriteOptions();
            callbacks.customizeUiComponent(optionsPane);
            //
            JButton optionsHelp = optionsPane.getOptionsHelp();
            optionsHelp.setIcon(iconHelp);
            optionsHelp.setEnabled(false);
            callbacks.customizeUiComponent(optionsHelp);
            //
            JButton optionsDefaults = optionsPane.getOptionsDefaults();
            optionsDefaults.setIcon(iconDefaults);
            callbacks.customizeUiComponent(optionsDefaults);
            //
            JButton optionsAddToken = optionsPane.getAddToken();
            callbacks.customizeUiComponent(optionsAddToken);
            optionsAddToken.addActionListener((e) -> {
                showTokenDialog("Add Token");
            });
            //
            JButton optionsEditToken = optionsPane.getEditToken();
            callbacks.customizeUiComponent(optionsEditToken);
            //
            JButton optionsRemoveToken = optionsPane.getRemoveToken();
            callbacks.customizeUiComponent(optionsRemoveToken);
            //
            JSplitPane optionsTokensTableSplitPane = optionsPane.getTokensTableSplitPane();
            callbacks.customizeUiComponent(optionsTokensTableSplitPane);
            //
            JTable optionsTokensTable = optionsPane.getTokensTable();
            callbacks.customizeUiComponent(optionsTokensTable);
            //
            optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            optionsTab.setFocusable(false);
            //optionsPane.requestFocus();
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(TokenRewriteExtension.this);
            // get burp frame and tabbed pane handler
            burpFrame = (JFrame) SwingUtilities.getWindowAncestor(optionsTab);
            // ...

        });
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

    //
    // TODO misc
    //
    private void showTokenDialog(String title) {
        JDialog dialog = new JDialog(burpFrame, title, Dialog.ModalityType.DOCUMENT_MODAL);
        TokenRewriteDialogWrapper wrapper = new TokenRewriteDialogWrapper();
        TokenRewriteEditPane editPane = new TokenRewriteEditPane();
        //editPane.setBounds(100, 100, 450, 400);
        wrapper.getScrollPane().getViewport().add(editPane);
        dialog.setBounds(100, 100, 450, 400);
        dialog.setContentPane(wrapper);
        dialog.setLocationRelativeTo(burpFrame);
        dialog.setVisible(true);
    }
}
