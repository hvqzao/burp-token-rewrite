// Token Rewrite Burp Extension, (c) 2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.rewrite;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.util.ArrayList;
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
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

public class TokenRewriteExtension implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    private JFrame burpFrame;
    private TokenRewriteOptions optionsPane;
    private ImageIcon iconHelp;
    private final ArrayList<TokenEntry> token = new ArrayList<>();
    private TokenTableModel tokenTableModel;

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
            optionsDefaults.setEnabled(false);
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

            // table
            tokenTableModel = new TokenTableModel();
            //tokenTableSorter = new TableRowSorter<>(tokenTableModel);
            optionsTokensTable.setModel(tokenTableModel);
            // optionsTokensTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            // optionsTokensTable.getTableHeader().setReorderingAllowed(true);
            optionsTokensTable.setAutoCreateRowSorter(true);
            //optionsTokensTable.setRowSorter(tokenTableSorter);
            for (int i = 0; i < tokenTableModel.getColumnCount(); i++) {
                TableColumn column = optionsTokensTable.getColumnModel().getColumn(i);
                column.setMinWidth(20);
                column.setPreferredWidth(tokenTableModel.getPreferredWidth(i));
            }
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
            //

            int row = token.size();
            token.add(new TokenEntry());
            token.add(new TokenEntry());
            token.add(new TokenEntry());
            tokenTableModel.fireTableRowsInserted(row, row);
            //
            //callbacks.printOutput("Loaded.");
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
        JCheckBox isRequestParameter = editPane.getIsRequestParameter();
        callbacks.customizeUiComponent(isRequestParameter);
        //
        JTextField requestParameter = editPane.getRequestParameter();
        callbacks.customizeUiComponent(requestParameter);
        //
        JCheckBox isCookie = editPane.getIsCookie();
        callbacks.customizeUiComponent(isCookie);
        //
        JTextField cookieName = editPane.getCookieName();
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
        //
        JButton ok = wrapper.getOkButton();
        callbacks.customizeUiComponent(ok);
        //
        JButton cancel = wrapper.getCancelButton();
        callbacks.customizeUiComponent(cancel);
        cancel.addActionListener((e) -> {
            dialog.dispose();
        });
        
        //
        dialog.setLocationRelativeTo(optionsTab);
        dialog.setVisible(true);
    }

    //
    class TokenTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return token.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TokenEntry tokenEntry = token.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return tokenEntry.isEnabled();
                case 1:
                    return true;
                default:
                    return "";
            }
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return true;
                default:
                    return false;
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            TokenEntry tokenEntry = token.get(rowIndex);
            tokenEntry.setEnabled((boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }

        
        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "Enabled";
                case 1:
                    return "Scope";
                case 2:
                    return "Parameter";
                case 3:
                    return "Cookie";
                case 4:
                    return "Search";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return Boolean.class;
                case 1:
                    return Boolean.class;
                default:
                    return String.class;
            }
        }

        public int getPreferredWidth(int column) {
            switch (column) {
                case 0:
                    return 60;
                case 1:
                    return 60;
                case 2:
                    return 80;
                case 3:
                    return 80;
                case 4:
                    return 140;
                default:
                    return 60;
            }
        }

    }

    //
    class TokenEntry {

        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
        
    }

    //
    //class TokenTable extends JTable {
    //
    //    public TokenTable(TableModel tableModel) {
    //        super(tableModel);
    //    }
    //
    //
    //}
}
