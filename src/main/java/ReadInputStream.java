import com.alibaba.fastjson.JSON;
import core.RootTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

/**
 * @author wq
 * @date 2019/5/27
 */
public class ReadInputStream {
    public static void main(String[] args) {
        Thread t1=new Thread(new Worker(),"ReadInputStream");
        t1.start();
    }
}

class Worker implements Runnable {
    //private static final Logger logger = LoggerFactory.getLogger(Worker.class);
    private final static String IPPUTFILEPATH = "D://pcap_flow.txt";
    private final static String OUTPUTFILEPATH = "D://pcap_flow_persist.json";
    private final static Integer FLOWLENGTH = 6;
    private static BufferedReader br = null;
    RootTable rootTable = new RootTable();

    static{
        try {
            br = new BufferedReader(new FileReader(IPPUTFILEPATH),1000000);
//            InputStreamReader isr = new InputStreamReader(new FileInputStream(FILEPATH), "UTF-8");
//            br = new BufferedReader(isr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() {
        String line = null;
        int count = 0;
        //while(true) {
            //synchronized(br) {
                try {
                    while((line = br.readLine()) != null) {
                        String[] ipFlow = line.split(",");
                        if(ipFlow.length != FLOWLENGTH) {
                            //logger.error("非法输入: " + line);
                            break;
                        }
                        //函数输入格式：源ip 目的ip 源端口 目的端口 协议 文件地址
                        rootTable.InsertIpFlow(ipFlow[0], ipFlow[2], ipFlow[1], ipFlow[3], ipFlow[4], ipFlow[5]);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
        //打印表中类容
        rootTable.toStr();
        //持久化
        String text = JSON.toJSONString(rootTable);
        System.out.println(text);
        try {
            FileOutputStream fos = new FileOutputStream(OUTPUTFILEPATH);
            fos.write(text.getBytes());
            fos.close();
        } catch (IOException e) {
        }
        //反序列化测试
        RootTable rootTable1 = JSON.parseObject(text, RootTable.class);
        rootTable1.toStr();

            //}
        //}
    }
}
