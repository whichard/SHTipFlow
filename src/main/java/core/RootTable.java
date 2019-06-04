package core;

import util.Parameter;
import util.StringHandle;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *流表 即根哈希表类
 **/

public class RootTable {

    //根哈希表节点类
    public class RootNode {

        public int IN = 0; //冲突计数器
        public boolean hasChild = false; //标志位  是否有子哈希表
        public Ic rootIc; //冲突链表
        public ChildTable childTable;//子哈希表

        @Override
        public String toString() {
            return "RootNode{" +
                    "冲突计数器=" + IN +
                    ", hasChild=" + hasChild +
                    ", 冲突链表=" + rootIc +
                    ", 子哈希表=" + childTable +
                    '}';
        }
    };

    public HashMap<Integer,RootNode> rootHashMap ; //根哈希表

    public RootTable() {
        rootHashMap = new HashMap<>(Parameter.rhSize);
    }

    /**
     * @description  往流表里加入一个Ip流
     * 1.算出hash value
     * 2.判断该value对应的节点是否为空  为空就加入 否则转3
     * 3.产生了冲突 IN+1  判断是否有子hash表
     * 4.若没有 判断IN 是否大于IN_Max              若没有则加入冲突链表 否则创建子哈希表
     * 5.若有  判断IN是否超过paper 46页的扩展公式  若超过进行扩展       否则加入子哈希表冲突链表
     * @param SA 源ip 字符串
     * @param DA 目的ip 字符串
     * @param SP 源端口 字符串
     * @param DP 目的端口 字符串
     * @param PT 协议类型 字符串
     * @param filePath pcap文件绝对路径
     * @return void
     * @date 2019/4/25
    */
    public void InsertIpFlow( String SA, String DA, String SP, String DP, String PT, String filePath ){

        //1 获得源ip 目的ip 源端口 目的端口的整数
        int Sip = StringHandle.ip2Int(SA);
        int Dip = StringHandle.ip2Int(DA);
        int Sport = StringHandle.port2Int(SP);
        int Dport = StringHandle.port2Int(DP);

        //2 取源ip  目的ip 低地址rhSize(根哈希表长度位数)位  获得根hash值
        int lowAddressSip = StringHandle.ipLowAddress(Sip,Parameter.rhSize);
        int lowAddressDip = StringHandle.ipLowAddress(Dip,Parameter.rhSize);
        int rootHashValue = Parameter.rootHash(lowAddressSip,lowAddressDip);

        //3判断根哈希表是否有该值
        if(rootHashMap.containsKey(rootHashValue)){
            //该位置存在ip流了 产生冲突
            RootNode rootNode = rootHashMap.get(rootHashValue); //获取该位置根节点
            rootNode.IN+=1;
            if(rootNode.hasChild){
                //若该节点已经存在子hash表
                ChildTable childTable = rootNode.childTable;
                if(childTable.chiladHashMapSize<(rootNode.IN*Parameter.adjust/Parameter.tolenrance)){
                    //满足paper49页式4-8 需要动态扩展子hash表
                    List<Ic.ImpactLinkNode> impactLinkNodes = childTable.getImpactNodes();
                    impactLinkNodes.add(new Ic().new ImpactLinkNode(SA,DA,SP,DP,PT,filePath,System.currentTimeMillis(),Parameter.defaultFrequency));
                    ChildTable newChildTable = childTable.createChildTableByImpactNodes(childTable.newSize(rootNode.IN),impactLinkNodes);
                    rootNode.childTable = newChildTable;
                }else {
                    //不需要扩展子hash表 直接在子hash表插入
                    childTable.InsertIpFlow(SA,DA,SP,DP,PT,filePath,System.currentTimeMillis(),Parameter.defaultFrequency);
                }
            }else {
                //该节点未存在子hash表
                if(rootNode.IN>=Parameter.INMax){
                    //达到冲突阀值 需要创建子哈希表
                    List<Ic.ImpactLinkNode> impactLinkNodes = new ArrayList<>();
                    for(Ic.ImpactLinkNode impactLinkNode:rootNode.rootIc.impactLinkedList){
                        impactLinkNodes.add(impactLinkNode);
                    }
                    impactLinkNodes.add(new Ic().new ImpactLinkNode(SA,DA,SP,DP,PT,filePath,System.currentTimeMillis(),Parameter.defaultFrequency));
                    ChildTable childTable = new ChildTable( (int) (Parameter.childTableLengthFactor * Parameter.INMax));
                    rootNode.childTable = childTable.createChildTableByImpactNodes((int) (Parameter.childTableLengthFactor * Parameter.INMax),impactLinkNodes);
                    rootNode.hasChild = true;
                    rootNode.rootIc = null;
                }else {
                    //未达到冲突阀值 直接插入已经存在的冲突链表
                    rootNode.rootIc.insertNewIpFlow(SA,DA,SP,DP,PT,filePath,System.currentTimeMillis(),Parameter.defaultFrequency);
                }
            }
        }else {
            //该位置不存在ip流 未产生冲突 也不存在冲突链表 新建冲突链表 加入该节点 令其最后活跃时间为当前时间  具有默认访问频度
            RootNode rootNode = new RootNode(); //生成一个根节点
            rootNode.rootIc = Ic.createIc(SA,DA,SP,DP,PT,filePath,System.currentTimeMillis(),Parameter.defaultFrequency);
            rootHashMap.put(rootHashValue,rootNode); //插入根哈希表
        }
    }

    /*@Override
    public RootTable clone() {
        RootTable rootTable = null;
        try {
            rootTable = (RootTable) super.clone();
            if(this.rootHashMap != null)
        } catch (Exception e) {
        }
        return rootTable;
    }*/

    public void toStr() {
        for (Map.Entry<Integer, RootNode> entry : rootHashMap.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
            for (Map.Entry<Integer, ChildTable.ChildNode> entry1 : entry.getValue().childTable.childHashMap.entrySet()) {
                System.out.println(entry1.getKey() + ": " + entry1.getValue());
            }
        }
    }
}

