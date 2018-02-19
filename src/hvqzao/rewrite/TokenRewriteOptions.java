package hvqzao.rewrite;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import static java.nio.file.Files.list;
import java.util.ArrayList;
import static java.util.Collections.list;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

public class TokenRewriteOptions extends JPanel implements IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private final ArrayList<TokenEntry> token = new ArrayList<>();
    private TokenTableModel tokenTableModel;
    private TokenEntry modalResult;
    private JFrame burpFrame;

    public TokenRewriteOptions() {
        initComponents();
        initialize();
    }

    private void initialize() {
        callbacks = BurpExtender.getCallbacks();

        callbacks.customizeUiComponent(this);
        callbacks.customizeUiComponent(optionsHelp);
        callbacks.customizeUiComponent(optionsDefaults);
        callbacks.customizeUiComponent(tokenTable);
        callbacks.customizeUiComponent(addToken);
        callbacks.customizeUiComponent(editToken);
        callbacks.customizeUiComponent(removeToken);
        callbacks.customizeUiComponent(tokensTableSplitPane);

        optionsHelp.setIcon(BurpExtender.getIconHelp());
        optionsHelp.setEnabled(false);
        //
        optionsDefaults.setIcon(BurpExtender.getIconDefaults());
        optionsDefaults.setEnabled(false);
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
        //
        addToken.addActionListener((e) -> {
            if (showTokenDialog("Add Token", null)) {
                int row = token.size();
                token.add(modalResult);
                tokenTableModel.fireTableRowsInserted(row, row);
            }
        });
        //
        editToken.addActionListener((e) -> {
            int selected = tokenTable.getSelectedRow();
            if (selected == - 1) {
                return;
            }
            TokenEntry tokenEntry = token.get(tokenTable.convertRowIndexToModel(selected));
            if (showTokenDialog("Edit Token", tokenEntry)) {
                int row = tokenTable.getSelectedRow();
                tokenTableModel.fireTableRowsUpdated(row, row);
            }
        });
        //
        removeToken.addActionListener((e) -> {
            int selected = tokenTable.getSelectedRow();
            if (selected == - 1) {
                return;
            }
            TokenEntry tokenEntry = token.get(tokenTable.convertRowIndexToModel(selected));
            int dialogResult = JOptionPane.showConfirmDialog(this, "Are you sure you want to remove it?", "Confirm", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (dialogResult == JOptionPane.YES_OPTION) {
                int index = tokenTable.convertRowIndexToModel(tokenTable.getSelectedRow());
                token.remove(index);
                int row = token.size();
                tokenTableModel.fireTableRowsDeleted(row, row);
            }
        });
    }

    public void start() {
        // get burp frame and tabbed pane handler
        burpFrame = (JFrame) SwingUtilities.getWindowAncestor(this.getParent());
        //
        tokensTableSplitPane.setDividerSize(10);
        //optionsTokensTableSplitPane.setContinuousLayout(true);
        tokensTableSplitPane.setUI(new GlyphSplitPaneUI(getBackground())); // each need separate instance
        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
    }

    //
    class TokenTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return token.size();
        }

        @Override
        public int getColumnCount() {
            return 6;
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
                    return tokenEntry.headerName;
                case 4:
                    return tokenEntry.cookieName;
                case 5:
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
                    return "Header";
                case 4:
                    return "Cookie";
                case 5:
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
                    return 70;
                case 2:
                    return 110;
                case 3:
                    return 110;
                case 4:
                    return 110;
                case 5:
                    return 180;
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
        private boolean updateHeader = false;
        private String headerName = "";
        private String paramName = "";
        private boolean urlEncodeValue = false;
        private boolean updateCookie = false;
        private String cookieName = "";
        private boolean logSet = false;
        private String value = null;
        private Pattern regexPattern = null;
        private boolean reIssue = false;
        private IHttpRequestResponse gotToken = null;

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
            this.regexPattern = null;
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
        
        public boolean isUpdateHeader() {
            return updateHeader;
        }

        public void setUpdateHeader(boolean updateHeader) {
            this.updateHeader = updateHeader;
        }

        public String getHeaderName() {
            return headerName;
        }
        
        public void setHeaderName(String headerName) {
            this.headerName = headerName;
        }

        public boolean isUrlEncodeValue() {
            return urlEncodeValue;
        }

        public void setUrlEncodeValue(boolean urlEncodeValue) {
            this.urlEncodeValue = urlEncodeValue;
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

        public Pattern getRegexPattern() {
            return regexPattern;
        }

        public void setRegexPattern(Pattern regexPattern) {
            this.regexPattern = regexPattern;
        }

        public boolean isReIssue() {
            return reIssue;
        }

        public void setReIssue(boolean reIssue) {
            this.reIssue = reIssue;
        }

        public IHttpRequestResponse getGotToken() {
            return gotToken;
        }

        public void setGotToken(IHttpRequestResponse gotToken) {
            this.gotToken = gotToken;
        }
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
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
                                t.setGotToken(messageInfo);
                                found = true;
                            }
                        }
                    } else {
                        // regex search
                        Pattern p = t.getRegexPattern();
                        if (p == null) {
                            p = Pattern.compile(t.getRegexMatch());
                            t.setRegexPattern(p);
                        }
                        Matcher m = p.matcher(responseString);
                        if (m.find()) {
                            t.setValue(m.group(1));
                            t.setGotToken(messageInfo);
                            found = true;
                        }
                    }
                    if (found) {
                        if (t.getLogGet()) {
                            // log get
                            callbacks.printOutput("Got value for " + tokenSearch(t) + ": \"" + t.getValue() + "\"");
                        }
                        if (t.isUpdateCookie()) {
                            // create cookie and add it to cookie jar
                            callbacks.updateCookieJar(new ICookie() {
                                @Override
                                public String getDomain() {
                                    return httpService.getHost();
                                }

                                @Override
                                public String getPath() {
                                    return null;
                                }

                                @Override
                                public Date getExpiration() {
                                    return null;
                                }

                                @Override
                                public String getName() {
                                    return t.getCookieName();
                                }

                                @Override
                                public String getValue() {
                                    return t.getValue();
                                }
                            });
                            if (t.getLogSet()) {
                                // log set cookie
                                callbacks.printOutput("Cookie " + t.getCookieName() + " set to: \"" + t.getValue() + "\"");
                            }
                        }
                    }
                } else if (t.getValue() != null && t.isUpdateParam()) {
                    // request
                    byte[] origRequest = messageInfo.getRequest();
                    //String requestString = helpers.bytesToString(request);
                    final String KEY = t.getParamName();
                    IParameter origParameter = helpers.getRequestParameter(origRequest, KEY);
                    if (origParameter != null) {
                        String value;
                        value = t.getValue();
                        if (t.isReIssue()) {
                            callbacks.makeHttpRequest(messageInfo.getHttpService(), t.getGotToken().getRequest());
                            value = t.getValue();
                        }
                        IParameter newParameter = null;
                        try {
                            newParameter = helpers.buildParameter(KEY, t.urlEncodeValue ? URLEncoder.encode(value, "UTF-8") : value, origParameter.getType());
                        } catch (UnsupportedEncodingException ex) {
                            ex.printStackTrace(BurpExtender.getStderr());
                        }
                        if (newParameter != null) {
                            try {
                                byte[] newRequest = helpers.updateParameter(origRequest, newParameter);
                                messageInfo.setRequest(newRequest);
                            } catch (Exception ex) {
                                ex.printStackTrace(BurpExtender.getStderr());
                            }
                            if (t.getLogSet()) {
                                // log set parameter
                                callbacks.printOutput("Parameter " + KEY + " set to: \"" + value + "\"");
                            }
                        }
                    }
                }else if (t.getValue() != null && t.isUpdateHeader()) {
                    IRequestInfo originalRequestInfo = helpers.analyzeRequest(messageInfo);
                    List<String> headers = originalRequestInfo.getHeaders();

                    final String KEY = t.getHeaderName();
                    final String VALUE = t.getValue();
                    
                        if (KEY != null) {
                            try{
                                for (String header: headers) {
                                    if(header.matches(KEY+".*")){
                                        headers.remove(header);
                                        //headers.remove(headerIndex);
                                        headers.add(KEY + ": " + VALUE);
                                        if (t.getLogSet()) {
                                            // log set parameter
                                            callbacks.printOutput("Parameter " + KEY + " set to: \"" + VALUE + "\"");
                                        }
                                        break;
                                    }
                                }
                            }catch(Exception ex){
                                ex.printStackTrace(BurpExtender.getStderr());
                            }
                        }

                    byte[] request = helpers.buildHttpMessage(headers, substring(messageInfo.getRequest(), originalRequestInfo.getBodyOffset()));

                    messageInfo.setRequest(request);
               }
            }
        });
    }
    
    //
    private byte[] substring(byte[] array, int from) {
        int len = array.length - from;
        byte[] subArray = new byte[len];
        System.arraycopy(array, from, subArray, 0, len);
        return subArray;
    }

    //
    // future use - issue specific json request using retrieved token and predefined key-value pairs
    //
    //private void issueJsonRequest(IHttpRequestResponse messageInfo, final String key, final String value) {
    //    IHttpService service = messageInfo.getHttpService();
    //    byte[] request = messageInfo.getRequest();
    //    IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
    //    String requestString = helpers.bytesToString(request);
    //
    //    String[] headers = requestString.substring(0, requestInfo.getBodyOffset()).trim().split("\n");
    //
    //    int marker = headers[0].lastIndexOf(" ");
    //    if (marker == -1) {
    //        // this should not happen
    //        return;
    //    }
    //    // modify url
    //    headers[0] = headers[0].substring(0, marker) + "/appended" + headers[0].substring(marker);
    //
    //    // prepare key-value pair as json to append to request body
    //    String extras = String.join(",",EXTRAS.entrySet().stream().map(e -> "\"" + e.getKey() + "\":\"" + e.getValue() + "\"\n").reduce((x, y) -> x + y).get().trim().split("\n"));
    //    String body = "{\"" + key + "\":\"" + value + "\"," + extras + "}";
    //
    //    byte[] message = helpers.buildHttpMessage(Arrays.asList(headers), helpers.stringToBytes(body));
    //    callbacks.makeHttpRequest(service, message);
    //}
    //
    // misc
    //
    private boolean tokenEntrySearchDefined(TokenEntry tokenEntry) {
        return ((tokenEntry.isLiteral() && (tokenEntry.getStartWith().length() != 0 && tokenEntry.getEndsWith().length() != 0))
                || (tokenEntry.isLiteral() == false && tokenEntry.getRegexMatch().length() != 0));
    }

    private String tokenSearch(TokenEntry tokenEntry) {
        if (tokenEntrySearchDefined(tokenEntry) == false) {
            return "Undefined";
        } else {
            return tokenEntry.isLiteral() ? tokenEntry.getStartWith() + "[...]" + tokenEntry.getEndsWith() : tokenEntry.getRegexMatch();
        }
    }

    private boolean showTokenDialog(String title, TokenEntry tokenEntry) {
        JDialog dialog = new JDialog(burpFrame, title, Dialog.ModalityType.DOCUMENT_MODAL);
        DialogWrapper wrapper = new DialogWrapper();
        TokenRewriteEditPane editPane = new TokenRewriteEditPane();
        // customize edit pane
        JButton editHelp = editPane.getEditHelp();
        editHelp.setIcon(BurpExtender.getIconHelp());
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
        JCheckBox isRequestHeader = editPane.getIsRequestHeader();
        callbacks.customizeUiComponent(isRequestHeader);
        //
        JTextField requestParameter = editPane.getRequestParameter();
        callbacks.customizeUiComponent(requestParameter);
        //
        JTextField requestHeader = editPane.getRequestHeader();
        callbacks.customizeUiComponent(requestHeader);
        //
        JCheckBox urlEncodeValue = editPane.getUrlEncodeValue();
        callbacks.customizeUiComponent(urlEncodeValue);
        //
        JCheckBox isCookie = editPane.getIsCookie();
        callbacks.customizeUiComponent(isCookie);
        //
        JTextField cookieName = editPane.getCookieName();
        //
        JCheckBox logSet = editPane.getLogSet();
        callbacks.customizeUiComponent(logSet);
        //
        JCheckBox issueRequest = editPane.getIssueRequest();
        callbacks.customizeUiComponent(issueRequest);
        //
        JButton editRequest = editPane.getEditRequest();
        callbacks.customizeUiComponent(editRequest);
        //
        JCheckBox reIssue = editPane.getReIssue();
        callbacks.customizeUiComponent(reIssue);
        //
        //isLiteral.requestFocus();
        // wrap editPane
        wrapper.getScrollPane().getViewport().add(editPane);
        dialog.setBounds(100, 100, 470, 500);
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
            isRequestHeader.setSelected(tokenEntry.isUpdateHeader());
            requestParameter.setText(tokenEntry.getParamName());
            requestHeader.setText(tokenEntry.getHeaderName());
            urlEncodeValue.setSelected(tokenEntry.isUrlEncodeValue());
            reIssue.setSelected(tokenEntry.isReIssue());
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
            modalResult.setUpdateHeader(isRequestHeader.isSelected());
            modalResult.setParamName(requestParameter.getText());
            modalResult.setHeaderName(requestHeader.getText());
            modalResult.setUrlEncodeValue(urlEncodeValue.isSelected());
            modalResult.setReIssue(reIssue.isSelected());
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
        dialog.setLocationRelativeTo(this.getParent());
        dialog.setVisible(true);
        //

        return modalResult != null;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        optionsHelp = new javax.swing.JButton();
        optionsDefaults = new javax.swing.JButton();
        optionsRewritePanel = new javax.swing.JPanel();
        optionsRewriteTitle = new javax.swing.JLabel();
        optionsRewriteDescription = new javax.swing.JLabel();
        addToken = new javax.swing.JButton();
        editToken = new javax.swing.JButton();
        removeToken = new javax.swing.JButton();
        tokensTableSplitPane = new javax.swing.JSplitPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        tokenTable = new javax.swing.JTable();

        setBorder(javax.swing.BorderFactory.createEmptyBorder(5, 5, 5, 5));

        optionsHelp.setMargin(new java.awt.Insets(0, 0, 0, 0));
        optionsHelp.setMaximumSize(new java.awt.Dimension(24, 24));
        optionsHelp.setMinimumSize(new java.awt.Dimension(24, 24));
        optionsHelp.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsDefaults.setMargin(new java.awt.Insets(0, 0, 0, 0));
        optionsDefaults.setMaximumSize(new java.awt.Dimension(24, 24));
        optionsDefaults.setMinimumSize(new java.awt.Dimension(24, 24));
        optionsDefaults.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsRewriteTitle.setText("<html><b style='color:#e58900;font-size:10px'>Token Rewrite</b></html>");

        optionsRewriteDescription.setText("<html>This extension allows you to get arbitrary value from responses and inject them into future requests. Those can be CSRF tokens, one-time codes etc.</html>");

        addToken.setText("Add");

        editToken.setText("Edit");

        removeToken.setText("Remove");

        tokensTableSplitPane.setDividerLocation(400);
        tokensTableSplitPane.setDividerSize(10);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 696, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 118, Short.MAX_VALUE)
        );

        tokensTableSplitPane.setRightComponent(jPanel1);

        tokenTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(tokenTable);

        tokensTableSplitPane.setLeftComponent(jScrollPane1);

        javax.swing.GroupLayout optionsRewritePanelLayout = new javax.swing.GroupLayout(optionsRewritePanel);
        optionsRewritePanel.setLayout(optionsRewritePanelLayout);
        optionsRewritePanelLayout.setHorizontalGroup(
            optionsRewritePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(optionsRewritePanelLayout.createSequentialGroup()
                .addComponent(optionsRewriteTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(optionsRewritePanelLayout.createSequentialGroup()
                .addGroup(optionsRewritePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(optionsRewriteDescription, javax.swing.GroupLayout.DEFAULT_SIZE, 836, Short.MAX_VALUE)
                    .addGroup(optionsRewritePanelLayout.createSequentialGroup()
                        .addGroup(optionsRewritePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(removeToken, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(editToken, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(addToken, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addComponent(tokensTableSplitPane, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        optionsRewritePanelLayout.setVerticalGroup(
            optionsRewritePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(optionsRewritePanelLayout.createSequentialGroup()
                .addComponent(optionsRewriteTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(optionsRewriteDescription, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(16, 16, 16)
                .addGroup(optionsRewritePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(optionsRewritePanelLayout.createSequentialGroup()
                        .addComponent(addToken)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(editToken)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeToken))
                    .addComponent(tokensTableSplitPane, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(optionsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(optionsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(optionsRewritePanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(optionsRewritePanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(optionsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(optionsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(29, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addToken;
    private javax.swing.JButton editToken;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton optionsDefaults;
    private javax.swing.JButton optionsHelp;
    private javax.swing.JLabel optionsRewriteDescription;
    private javax.swing.JPanel optionsRewritePanel;
    private javax.swing.JLabel optionsRewriteTitle;
    private javax.swing.JButton removeToken;
    private javax.swing.JTable tokenTable;
    private javax.swing.JSplitPane tokensTableSplitPane;
    // End of variables declaration//GEN-END:variables
}
