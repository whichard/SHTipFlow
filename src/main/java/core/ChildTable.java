package core;

import util.Parameter;
import util.StringHandle;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 *子哈希表类
 **/

public class ChildTable {

    //子哈希表节点类
    public class ChildNode {
        public Ic childIc;  //子哈希表冲突链表

        @Override
        public String toString() {
            return "ChildNode{" +
                    "childIc=" + childIc +
                    '}';
        }
    }

    //子哈希表
    public HashMap<Integer, ChildNode> childHashMap;

    //子哈希表大小
    public int chiladHashMapSize;

    public ChildTable() {
        //this.chiladHashMapSize = chiladHashMapSize;
        childHashMap = new HashMap<>();
    }

    public ChildTable(int chiladHashMapSize) {
        this.chiladHashMapSize = chiladHashMapSize;
        childHashMap = new HashMap<>(chiladHashMapSize);
    }

    /**
     * @description 创建一个空的子hash表
     * @param  chiladHashMapSize 子hash表大小
     * @return core.ChildTable 子hash表
     * @date 2019/4/25
     */
    public static ChildTable createEmptyChildTable(int chiladHashMapSize) {
        ChildTable childTable = new ChildTable(chiladHashMapSize);
        return childTable;
    }

    /**
     *@description 存在子hash表时，往子hash表中插入一个Ip流
     * @param SA        源ip
     * @param DA        目的ip
     * @param SP        源端口
     * @param DP        目的端口
     * @param PT        协议类型
     * @param filePath  pcap文件路径
     * @param lastTime  最后活跃时间
     * @param frequency 访问频度
     * @return void     无返回值
     * 1.判断该位置是否有冲突链表 没有的话创建并插入
     * 2.有的话 直接插入
     * @date 2019/4/25
     */
    public void InsertIpFlow(String SA, String DA, String SP, String DP, String PT, String filePath, long lastTime, int frequency) {
        //1 获得源ip 目的ip 源端口 目的端口的整数
        int Sip = StringHandle.ip2Int(SA);
        int Dip = StringHandle.ip2Int(DA);
        int Sport = StringHandle.port2Int(SP);
        int Dport = StringHandle.port2Int(DP);

        //2 获得子hash值
        int childHashValue = Parameter.chHash(Sip, Dip, Sport, Dport, Integer.toBinaryString(chiladHashMapSize).length());

        if (childHashMap.containsKey(childHashValue)) {
            //该位置存在冲突链表 插入该冲突链表
            childHashMap.get(childHashValue).childIc.insertNewIpFlow(SA, DA, SP, DP, PT, filePath, lastTime, frequency);
        } else {
            //该位置不存在冲突链表，新建冲突链表 将此流作为第一个结点插入
            ChildNode childNode = new ChildNode();
            Ic ic = Ic.createIc(SA, DA, SP, DP, PT, filePath, lastTime, frequency);
            childNode.childIc = ic;
            childHashMap.put(childHashValue, childNode);
        }
    }

    /**
     * @description 不存在子hash表或者重构子哈希表时    根据冲突链表节点数组 生成新的子哈希表
     * @param size  子哈希表大小
     * @param impactLinkNodes  冲突链表节点数组
     * @return core.ChildTable  子哈希表
     * @date 2019/4/28
    */
    public ChildTable createChildTableByImpactNodes(int size , List<Ic.ImpactLinkNode> impactLinkNodes){
         ChildTable newChildTable = new ChildTable(size);
         for(Ic.ImpactLinkNode impactLinkNode:impactLinkNodes){
             //1 获得源ip 目的ip 源端口 目的端口的整数
             int Sip = StringHandle.ip2Int(impactLinkNode.SA);
             int Dip = StringHandle.ip2Int(impactLinkNode.DA);
             int Sport = StringHandle.port2Int(impactLinkNode.SP);
             int Dport = StringHandle.port2Int(impactLinkNode.DP);

             //2 获得子hash值
             int childHashValue = Parameter.chHash(Sip, Dip, Sport, Dport, Integer.toBinaryString(chiladHashMapSize).length());

             if (childHashMap.containsKey(childHashValue)) {
                 //该位置存在冲突链表 插入该冲突链表
                 childHashMap.get(childHashValue).childIc.insertExistIpFlow(impactLinkNode);
             } else {
                 //该位置不存在冲突链表，新建冲突链表 并插入
                 ChildNode childNode = new ChildNode();
                 Ic ic = new Ic();
                 ic.insertExistIpFlow(impactLinkNode);
                 childNode.childIc = ic;
                 childHashMap.put(childHashValue, childNode);
             }

         }
         return newChildTable;
    }

    /**
     * @description  从子哈希表中获得所有的冲突节点
     * @param  void  无参数
     * @return java.util.List  冲突节点列表
     * @date 2019/4/28
    */
    public List<Ic.ImpactLinkNode>  getImpactNodes(){
        List<Ic.ImpactLinkNode> impactLinkNodes = new ArrayList<>();
        for(ChildNode childNode:childHashMap.values()){
            //如果该节点有冲突链表
            if(childNode.childIc.impactLinkedList.size()>0){
                for(Ic.ImpactLinkNode impactLinkNode:childNode.childIc.impactLinkedList){
                    impactLinkNodes.add(impactLinkNode);
                }
            }
        }
        return impactLinkNodes;
    }

    /**
     * @description  计算子哈希表扩展后的新大小
     * @param IN  冲突计数器
     * @return int  新大小
     * @date 2019/4/28
    */
    public int newSize(int IN){
        return (int) (IN*Parameter.adjust);
    }
}


