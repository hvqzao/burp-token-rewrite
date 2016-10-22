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
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class TokenRewriteExtension implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    private JFrame burpFrame;
    private TokenRewriteOptions optionsPane;
    private ImageIcon iconHelp;

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
            iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/rewrite/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            ImageIcon iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/rewrite/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            Dimension iconDimension = new Dimension(24, 24);
            // extension tab
            optionsPane = new TokenRewriteOptions();
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
        // customize edit pane
        JButton editHelp = editPane.getEditHelp();
        editHelp.setIcon(iconHelp);
        editHelp.setEnabled(false);
        callbacks.customizeUiComponent(editHelp);
        //
        JCheckBox isInScope = editPane.getIsInScope();
        callbacks.customizeUiComponent(isInScope);
        //
        JRadioButton isLiteral = editPane.getIsLiteral();
        callbacks.customizeUiComponent(isLiteral);
        //
        JTextField startWith = editPane.getStartWith();
        callbacks.customizeUiComponent(startWith);
        //
        JTextField endsWith = editPane.getEndsWith();
        callbacks.customizeUiComponent(endsWith);
        //
        JRadioButton isRegex = editPane.getIsRegex();
        callbacks.customizeUiComponent(isRegex);
        //
        JTextField regexMatch = editPane.getRegexMatch();
        callbacks.customizeUiComponent(regexMatch);
        //
        JCheckBox logGet = editPane.getLogGet();
        callbacks.customizeUiComponent(logGet);
        //

        //
        JCheckBox logSet = editPane.getLogSet();
        callbacks.customizeUiComponent(logSet);
        //
        isLiteral.requestFocus();
        // wrap editPane
        wrapper.getScrollPane().getViewport().add(editPane);
        dialog.setBounds(100, 100, 470, 470);
        dialog.setContentPane(wrapper);
        //dialog.setLocationRelativeTo(burpFrame);
        //dialog.setLocationRelativeTo(optionsPane.getOptionsRewritePanel());
        dialog.setLocationRelativeTo(optionsTab);
        dialog.setVisible(true);
    }
}
