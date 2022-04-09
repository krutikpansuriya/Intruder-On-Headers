/*
 * Intruder-on-Header
 *
 * Generate markers on header values in intruder.
 * - Useful for fuzzing header values.
 * - Easy mode enabled: right click to Send to Intruder-on-Header.
 *
 * Author: Krutik Pansuriya (Motabhai)
 * Date: 07/04/2022
 * Version: 1.0
 */

package burp;
import java.net.URL;
import java.util.*;
import javax.swing.JMenuItem;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpExtender implements IBurpExtender, IContextMenuFactory,IIntruderPayloadGeneratorFactory {
    //global variables
    public static String MENU_NAME_1 = "Headers+Parameter";
    public static String MENU_NAME_2 = "Only Headers";
    public static String MENU_NAME_3 = "Headers+Parameter+URL+HTTP_Method";
    public IBurpExtenderCallbacks mycallbacks;
    public IExtensionHelpers helpers;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        //setup the callbacks
        this.mycallbacks = callbacks;
        this.helpers = mycallbacks.getHelpers();
        mycallbacks.setExtensionName("Intruder-on-Header");
        mycallbacks.registerContextMenuFactory(this);
        mycallbacks.registerIntruderPayloadGeneratorFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        //register menu item for only menus [0,2,4,6]
        if (invocation.getInvocationContext()%2 == 0 && invocation.getInvocationContext() < 8) {
            //new 'Send To Intruder-on-Header' button
            List<JMenuItem> ret = new LinkedList<JMenuItem>();
            JMenuItem menuItem_1 = new JMenuItem(MENU_NAME_1);
            JMenuItem menuItem_2 = new JMenuItem(MENU_NAME_2);
            JMenuItem menuItem_3 = new JMenuItem(MENU_NAME_3);
            menuItem_1.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent action) {
                    //if clicked on button
                    if (action.getActionCommand().equals(MENU_NAME_1)) {
                        IHttpRequestResponse item[] = invocation.getSelectedMessages();
                        //grab request
                        IHttpRequestResponse first = item[0];
                        //ternary operator return false is http, else return true
                        Boolean is_secure = (first.getHttpService().getProtocol().toString() == "http") ? false : true;
                        //set payload positions as method and root node
                        List<int[]> payload_positions = getPayloadPos_1(first);
                        //create a new intruder with selected
                        mycallbacks.sendToIntruder(first.getHttpService().getHost(),first.getHttpService().getPort(), is_secure, first.getRequest(),payload_positions);
                    }
                }
            });
            menuItem_2.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent action) {
                    //if clicked on button
                    if (action.getActionCommand().equals(MENU_NAME_2)) {
                        IHttpRequestResponse item[] = invocation.getSelectedMessages();
                        //grab request
                        IHttpRequestResponse first = item[0];
                        //ternary operator return false is http, else return true
                        Boolean is_secure = (first.getHttpService().getProtocol().toString() == "http") ? false : true;
                        //set payload positions as method and root node
                        List<int[]> payload_positions = getPayloadPos_2(first);
                        //create a new intruder with selected
                        mycallbacks.sendToIntruder(first.getHttpService().getHost(),first.getHttpService().getPort(), is_secure, first.getRequest(),payload_positions);
                    }
                }
            });
            menuItem_3.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent action) {
                    //if clicked on button
                    if (action.getActionCommand().equals(MENU_NAME_3)) {
                        IHttpRequestResponse item[] = invocation.getSelectedMessages();
                        //grab request
                        IHttpRequestResponse first = item[0];
                        //ternary operator return false is http, else return true
                        Boolean is_secure = (first.getHttpService().getProtocol().toString() == "http") ? false : true;
                        //set payload positions as method and root node
                        List<int[]> payload_positions = getPayloadPos_3(first);
                        //create a new intruder with selected
                        mycallbacks.sendToIntruder(first.getHttpService().getHost(),first.getHttpService().getPort(), is_secure, first.getRequest(),payload_positions);
                    }
                }
            });
            ret.add(menuItem_1);
            ret.add(menuItem_2);
            ret.add(menuItem_3);
            return (ret);
        }
        //No new menu on other
        return null;
    }

    public List<int[]> getPayloadPos_2(IHttpRequestResponse first) {
        List<String> iheaders = mycallbacks.getHelpers().analyzeRequest(first).getHeaders();
        String req = helpers.bytesToString(first.getRequest());
        List<int[]> payload_positions = new ArrayList<int[]>();
        for (String header : iheaders) {
            if (header == iheaders.get(0)) continue;
            int start_offset = req.indexOf(" ",req.indexOf(header))+1;
            int offset = req.indexOf(header);
            int end_offset = offset+header.length();
            int arr[]={start_offset,end_offset};
            payload_positions.add(arr);
        }
        return payload_positions;
    }

    public List<int[]> getPayloadPos_1(IHttpRequestResponse first) {
        List<IParameter> para = mycallbacks.getHelpers().analyzeRequest(first).getParameters();
        String req = helpers.bytesToString(first.getRequest());
        List<String> iheaders = mycallbacks.getHelpers().analyzeRequest(first).getHeaders();
        List<int[]> payload_positions = new ArrayList<int[]>();
        String cook = "Cookie";
        for (IParameter ipara : para) {
            int start_offset= getParameterSPos(ipara);
            int end_offset= getParameterEPos(ipara);
            int arr[] = {start_offset, end_offset};
            payload_positions.add(arr);
        }
        for (String header : iheaders) {
            if (header == iheaders.get(0)) {
                continue;
            }
            if (header.contains(cook) == true) {
                continue;
            }
            int start_offset = req.indexOf(" ",req.indexOf(header))+1;
            int offset = req.indexOf(header);
            int end_offset = offset+header.length();
            int arr[]={start_offset,end_offset};
            payload_positions.add(arr);
        }
        Collections.sort(payload_positions, new Comparator<int[]>() {
            @Override
            public int compare(int[] a, int[] b) {
                return a[a.length-1] -b[b.length-1];
            }
        });
         return payload_positions;
    }

    public int getParameterSPos(IParameter para) {
        int pos = para.getValueStart();
        return pos;
    }
    public int getParameterEPos(IParameter para) {
        int pos = para.getValueEnd();
        return pos;
    }

    public List<int[]> getPayloadPos_3(IHttpRequestResponse first) {
        List<IParameter> para = mycallbacks.getHelpers().analyzeRequest(first).getParameters();
        String req = helpers.bytesToString(first.getRequest());
        List<String> iheaders = mycallbacks.getHelpers().analyzeRequest(first).getHeaders();
        List<int[]> payload_positions = new ArrayList<int[]>();
        String cook = "Cookie";
        for (IParameter ipara : para) {
            int start_offset= getParameterSPos(ipara);
            int end_offset= getParameterEPos(ipara);
            int arr[] = {start_offset, end_offset};
            payload_positions.add(arr);
        }
        for (String header : iheaders) {
            if (header == iheaders.get(0)) {
                continue;
            }
            if (header.contains(cook) == true) {
                continue;
            }
            int start_offset = req.indexOf(" ",req.indexOf(header))+1;
            int offset = req.indexOf(header);
            int end_offset = offset+header.length();
            int arr[]={start_offset,end_offset};
            payload_positions.add(arr);
        }
        int[] method_pos = getHttpMethod(first);
        int start_dir = method_pos[1] + 1;
        int end_dir = start_dir + mycallbacks.getHelpers().analyzeRequest(first).getUrl().getPath().length();
        int[] dir_pos = { start_dir, end_dir };
        //List<int[]> payload_positions = new ArrayList<int[]>();
        payload_positions.add(method_pos);
        payload_positions.add(dir_pos);

        Collections.sort(payload_positions, new Comparator<int[]>() {
            @Override
            public int compare(int[] a, int[] b) {
                return a[a.length-1] -b[b.length-1];
            }
        });
        return payload_positions;
    }
    public int[] getHttpMethod(IHttpRequestResponse req) {
        String req_string = helpers.bytesToString(req.getRequest());
        //up to the first space - the method
        int[] method_pos = { 0, req_string.indexOf(" ") };
        return method_pos;
    }
    @Override
    public String getGeneratorName() {
        return null;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack iIntruderAttack) {
        return null;
    }
}