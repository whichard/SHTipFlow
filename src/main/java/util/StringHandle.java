package util;

/**
 *该类用于处理字符串
 * 如将ip地址 和 端口 转化为int整数
 * 取ip的低地址n位
 **/

public class StringHandle {

    /**
     * @description 将Ip地址转为int整数
     * @param ipString  ip地址 点分十进制字符串 如192.168.1.1
     * @return int   对应的Int整数
     * @date 2019/4/25
    */
   public static int ip2Int(String ipString) {
        // 取 ip 的各段
        String[] ipSlices = ipString.split("\\.");
        int rs = 0;
        try {
            for (int i = 0; i < ipSlices.length; i++) {
                // 将 ip 的每一段解析为 int，并根据位置左移 8 位
                int intSlice = Integer.parseInt(ipSlices[i]) << 8 * i;
                // 或运算
                rs = rs | intSlice;
            }
        } catch (Exception e) {
        }
        return rs;
    }

    /**
     * @description  端口号转成Int整数
     * @param portString  端口号字符串
     * @return int 端口号整数
     * @date 2019/4/25
    */
    public static int port2Int(String portString){
       return Integer.valueOf(portString);
    }

    /**
     * @description  取Ip地址的低N位
     * @param ip     整数ip地址
     * @param n      取多少位
     * @return int   取n位后的整数
     * @date 2019/4/25
    */
    public static int ipLowAddress(int ip , int n){
        String binaryString = Integer.toBinaryString(ip);
        int res = 0;
        try {
            res = Integer.parseInt(binaryString.substring(binaryString.length()-n,binaryString.length()),2);
        } catch (Exception e){
        }
        return res;
    }

}
