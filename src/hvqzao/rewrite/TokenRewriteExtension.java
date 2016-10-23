// Token Rewrite Burp Extension, (c) 2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.rewrite;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.ITab;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

public class TokenRewriteExtension implements IBurpExtender, ITab, IHttpListener {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    private JFrame burpFrame;
    private TokenRewriteOptions optionsPane;
    private ImageIcon iconHelp;
    private final ArrayList<TokenEntry> token = new ArrayList<>();
    private TokenTableModel tokenTableModel;
    private TokenEntry modalResult;

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
            JSplitPane optionsTokensTableSplitPane = optionsPane.getTokensTableSplitPane();
            callbacks.customizeUiComponent(optionsTokensTableSplitPane);
            //
            JTable tokenTable = optionsPane.getTokensTable();
            // table
            tokenTableModel = new TokenTableModel();
            //tokenTableSorter = new TableRowSorter<>(tokenTableModel);
            tokenTable.setModel(tokenTableModel);
            // optionsTokensTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            // optionsTokensTable.getTableHeader().setReorderingAllowed(true);
            tokenTable.setAutoCreateRowSorter(true);
            //optionsTokensTable.setRowSorter(tokenTableSorter);
            for (int i = 0; i < tokenTableModel.getColumnCount(); i++) {
                TableColumn column = tokenTable.getColumnModel().getColumn(i);
                column.setMinWidth(20);
                column.setPreferredWidth(tokenTableModel.getPreferredWidth(i));
            }
            callbacks.customizeUiComponent(tokenTable);
            //
            JButton optionsAddToken = optionsPane.getAddToken();
            callbacks.customizeUiComponent(optionsAddToken);
            optionsAddToken.addActionListener((e) -> {
                if (showTokenDialog("Add Token", null)) {
                    int row = token.size();
                    token.add(modalResult);
                    tokenTableModel.fireTableRowsInserted(row, row);
                }
            });
            //
            JButton optionsEditToken = optionsPane.getEditToken();
            callbacks.customizeUiComponent(optionsEditToken);
            optionsEditToken.addActionListener((e) -> {
                TokenEntry tokenEntry = token.get(tokenTable.convertRowIndexToModel(tokenTable.getSelectedRow()));
                if (showTokenDialog("Edit Token", tokenEntry)) {
                    int row = tokenTable.getSelectedRow();
                    tokenTableModel.fireTableRowsUpdated(row, row);
                }
            });
            //
            JButton optionsRemoveToken = optionsPane.getRemoveToken();
            callbacks.customizeUiComponent(optionsRemoveToken);
            optionsRemoveToken.addActionListener((e) -> {
                TokenEntry tokenEntry = token.get(tokenTable.convertRowIndexToModel(tokenTable.getSelectedRow()));
                int dialogResult = JOptionPane.showConfirmDialog(optionsPane, "Are you sure you want to remove it?", "Confirm", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (dialogResult == JOptionPane.YES_OPTION) {
                    int index = tokenTable.convertRowIndexToModel(tokenTable.getSelectedRow());
                    token.remove(index);
                    int row = token.size();
                    tokenTableModel.fireTableRowsDeleted(row, row);
                }
            });
            //
            optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            optionsTab.setFocusable(false);
            //optionsPane.requestFocus();
            //
            optionsTokensTableSplitPane.setDividerSize(10);
            //optionsTokensTableSplitPane.setContinuousLayout(true);
            optionsTokensTableSplitPane.setUI(new GlyphSplitPaneUI(optionsPane.getBackground())); // each need separate instance
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(TokenRewriteExtension.this);
            // get burp frame and tabbed pane handler
            burpFrame = (JFrame) SwingUtilities.getWindowAncestor(optionsTab);
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
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        token.stream().filter(t -> t.isEnabled()).forEach((TokenEntry t) -> {
            //
            IHttpService httpService = messageInfo.getHttpService();
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            if (t.isInScope() == false || callbacks.isInScope(requestInfo.getUrl())) {
                if (messageIsRequest == false && tokenEntrySearchDefined(t)) {
                    // response
                    byte[] response = messageInfo.getResponse();
                    //IResponseInfo responseInfo = helpers.analyzeResponse(response);
                    String responseString = helpers.bytesToString(response);
                    boolean found = false;
                    if (t.isLiteral()) {
                        // literal search
                        final String START = t.getStartWith();
                        int start = responseString.indexOf(START);
                        if (start > -1) {
                            start += START.length();
                            final String END = t.getEndsWith();
                            int length = responseString.substring(start).indexOf(END);
                            if (length > -1) {
                                t.setValue(responseString.substring(start, start + length));
                                found = true;
                            }
                        }
                    } else {
                        // regex search

                    }
                    if (found) {
                        if (t.getLogGet()) {
                            // log get
                            callbacks.printOutput("Got value for " + tokenSearch(t) + ": " + t.getValue());
                        }
                        if (t.isUpdateCookie()) {
                            // set cookie

                            if (t.getLogSet()) {
                                // log set cookie

                            }
                        }
                    }
                } else if (t.getValue() != null && t.isUpdateParam()) {
                    // request

                    {

                        if (t.getLogSet()) {
                            // log set parameter

                        }
                    }
                }
            }
        });
    }

    //
    // TODO misc
    //
    private boolean tokenEntrySearchDefined(TokenEntry tokenEntry) {
        return ((tokenEntry.isLiteral() && (tokenEntry.getStartWith().length() == 0 || tokenEntry.getEndsWith().length() == 0))
                || (tokenEntry.isLiteral() == false && tokenEntry.getRegexMatch().length() == 0));
    }

    private String tokenSearch(TokenEntry tokenEntry) {
        if (tokenEntrySearchDefined(tokenEntry)) {
            return "Undefined";
        } else {
            return tokenEntry.isLiteral() ? tokenEntry.getStartWith() + "[...]" + tokenEntry.getEndsWith() : tokenEntry.getRegexMatch();
        }
    }

    private boolean showTokenDialog(String title, TokenEntry tokenEntry) {
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
        if (tokenEntry != null) {
            isInScope.setSelected(tokenEntry.isInScope());
            if (tokenEntry.isLiteral()) {
                isLiteral.setSelected(true);
            } else {
                isRegex.setSelected(true);
            }
            startWith.setText(tokenEntry.getStartWith());
            endsWith.setText(tokenEntry.getEndsWith());
            regexMatch.setText(tokenEntry.getRegexMatch());
            logGet.setSelected(tokenEntry.getLogGet());
            isRequestParameter.setSelected(tokenEntry.isUpdateParam());
            requestParameter.setText(tokenEntry.getParamName());
            isCookie.setSelected(tokenEntry.isUpdateCookie());
            cookieName.setText(tokenEntry.getCookieName());
            logSet.setSelected(tokenEntry.getLogSet());
        }

        //
        modalResult = null;
        //
        JButton ok = wrapper.getOkButton();
        callbacks.customizeUiComponent(ok);
        ok.addActionListener((ActionEvent e) -> {
            modalResult = tokenEntry;
            if (modalResult == null) {
                modalResult = new TokenEntry();
            }
            modalResult.setInScope(isInScope.isSelected());
            modalResult.setLiteral(isLiteral.isSelected());
            modalResult.setStartWith(startWith.getText());
            modalResult.setEndsWith(endsWith.getText());
            modalResult.setRegexMatch(regexMatch.getText());
            modalResult.setLogGet(logGet.isSelected());
            modalResult.setUpdateParam(isRequestParameter.isSelected());
            modalResult.setParamName(requestParameter.getText());
            modalResult.setUpdateCookie(isCookie.isSelected());
            modalResult.setCookieName(cookieName.getText());
            modalResult.setLogSet(logSet.isSelected());
            //
            dialog.dispose();
        });
        //
        JButton cancel = wrapper.getCancelButton();
        callbacks.customizeUiComponent(cancel);
        cancel.addActionListener((e) -> {
            dialog.dispose();
        });
        //
        dialog.setLocationRelativeTo(optionsTab);
        dialog.setVisible(true);
        //

        return modalResult != null;
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
                    return tokenEntry.isInScope();
                case 2:
                    return tokenEntry.paramName;
                case 3:
                    return tokenEntry.cookieName;
                case 4:
                    return tokenSearch(tokenEntry);
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
                    return 80;
                case 1:
                    return 80;
                case 2:
                    return 80;
                case 3:
                    return 80;
                case 4:
                    return 140;
                default:
                    return 80;
            }
        }

    }

    //
    class TokenEntry {

        private boolean enabled = true;
        private boolean inScope = false;
        private boolean literal = true;
        private String startWith = "";
        private String endsWith = "";
        private String regexMatch = "";
        private boolean logGet = false;
        private boolean updateParam = false;
        private String paramName = "";
        private boolean updateCookie = false;
        private String cookieName = "";
        private boolean logSet = false;
        private String value = null;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isInScope() {
            return inScope;
        }

        public void setInScope(boolean inScope) {
            this.inScope = inScope;
        }

        public boolean isLiteral() {
            return literal;
        }

        public void setLiteral(boolean literal) {
            this.literal = literal;
        }

        public String getStartWith() {
            return startWith;
        }

        public void setStartWith(String startWith) {
            this.startWith = startWith;
        }

        public String getEndsWith() {
            return endsWith;
        }

        public void setEndsWith(String endsWith) {
            this.endsWith = endsWith;
        }

        public String getRegexMatch() {
            return regexMatch;
        }

        public void setRegexMatch(String regexMatch) {
            this.regexMatch = regexMatch;
        }

        public boolean getLogGet() {
            return logGet;
        }

        public void setLogGet(boolean logGet) {
            this.logGet = logGet;
        }

        public boolean isUpdateParam() {
            return updateParam;
        }

        public void setUpdateParam(boolean updateParam) {
            this.updateParam = updateParam;
        }

        public String getParamName() {
            return paramName;
        }

        public void setParamName(String paramName) {
            this.paramName = paramName;
        }

        public boolean isUpdateCookie() {
            return updateCookie;
        }

        public void setUpdateCookie(boolean updateCookie) {
            this.updateCookie = updateCookie;
        }

        public String getCookieName() {
            return cookieName;
        }

        public void setCookieName(String cookieName) {
            this.cookieName = cookieName;
        }

        public boolean getLogSet() {
            return logSet;
        }

        public void setLogSet(boolean logSet) {
            this.logSet = logSet;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
