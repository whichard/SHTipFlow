package util;

/**
 *该类放置各种参数以及使用的hash函数
 **/

public class Parameter {

    public static final int rhLen = 0x03FF; //根哈希长度大小
    public static final int rhSize = Integer.toBinaryString(Integer.valueOf(String.valueOf(rhLen))).length(); //根hash长度位数 e.g.10位
    public static final double childTableLengthFactor = 2.0; //子哈希表调整因子 每新建一个子哈希表 默认长度为 int(chilidTableFactor * INMax)
    public static final int INMax = 6 ; //冲突阀值 超过该阀值建立子哈希表
    public static final int defaultFrequency=0 ;//缺省访问频度
    public static final long Texp= 1000 * 3600 ; //会话超时计时器 超过该时间则清理节点  单位ms
    public static final double tolenrance = 2.0 ; //paper 46页  容忍系数 超过临界值扩容子哈希表
    public static final double adjust = 1.0; //paper 46页 调整系数


    /**
     * @description 根hash算法
     * @param SA    源ip 32位二进制数 如果超过rhSize位 取低地址rhSize位
     * @param DA    目的ip 32位二进制数 如果超过rhSize位 取低地址rhSize位
     * @return int  返回一个rhSize位 的hash值
     * @date 2019/4/25
    */
    public static int rootHash(int SA , int DA){
        return (((SA>>8)&rhLen) | ((DA>>8)&rhLen)) & rhLen ;
    }


    /**
     * @description  子hash算法
     * @param SA      源32位ip
     * @param DA      目的32位ip
     * @param SP      源端口
     * @param DP      目的端口
     * @param chHashTableSize 子hash表长度所占据的二进制位数
     * @return int    hash值
     * @date 2019/4/25
    */
    public static int chHash(int SA, int DA, int SP, int DP,int chHashTableSize){
        int f1 = SA;
        int f2 = DA;
        int f3 = SP | DP ;
        int v1 = f1 ^ f2;
        int v2 = f3;
        int h1 = v1<<8;
        h1 ^= v1>>4 ;
        h1 ^= v1>>12;
        h1 ^= v1>>16;
        h1 ^= v2<<6;
        h1 ^= v2<<10;
        h1 ^= v2<<14;
        h1 ^= v2>>7;
        h1 ^=((h1<<16)>>16)>>chHashTableSize;
        int value = (h1<<(32-chHashTableSize))>>(32-chHashTableSize);
        return value;
    }
}
