package core;

import util.FileUtil;
import util.Parameter;

import java.util.LinkedList;

/**
 *冲突链表类
 **/

public class Ic {

    public class ImpactLinkNode {

        public String SA; // 源IP
        public String DA; //目的Ip
        public String SP; //源端口
        public String DP; //目的端口
        public String PT; //协议类型
        public String filePath; //pcap文件路径
        public long lastTime; //节点最后一次活跃的时间

        public int frequency; //访问频度 2倍于前面的节点的话就提前

        public ImpactLinkNode(String SA, String DA, String SP, String DP, String PT, String filePath,long lastTime,int frequency) {
            this.SA = SA;
            this.DA = DA;
            this.SP = SP;
            this.DP = DP;
            this.PT = PT;
            this.filePath = filePath;
            this.lastTime = lastTime;
            this.frequency = frequency;
        }
    }
    
    public LinkedList<ImpactLinkNode> impactLinkedList ; //冲突链表

    public Ic() {
        impactLinkedList = new LinkedList<>();
    }

    /**
     * @description  创建一个冲突链表 并插入第一个ip流
     * @param SA     源ip
     * @param DA     目的ip
     * @param SP     源端口
     * @param DP     目的端口
     * @param PT      协议
     * @param filePath  文件路径
     * @param lastTime 最后活跃时间
     * @param frequency 访问频度
     * @return core.Ic   冲突链表
     * @date 2019/4/25
     */
    public static Ic createIc(String SA, String DA, String SP, String DP, String PT,String filePath,long lastTime,int frequency){
        Ic ic = new Ic();  //生成一个冲突链表
        Ic.ImpactLinkNode impactLinkNode = ic.new ImpactLinkNode(SA,DA,SP,DP,PT,filePath,lastTime,frequency); //生成一个冲突链表节点 具有默认访问频度
        ic.impactLinkedList.addFirst(impactLinkNode); //paper47页  对于新流给予较高的缺省频度 置于IC头部
        return ic;
    }

    /**
     * @description 往冲突链表中插入一个Ip流 此IP流是新到的
     * @param SA    源ip
     * @param DA    目的ip
     * @param SP    源端口
     * @param DP    目的端口
     * @param PT    协议类型
     * @param filePath   pcap文件路径
     * @param lastTime  ip流最后活跃时间
     * @param frequency 访问频度
     * @return void 无返回值
     * @date 2019/4/25
     */
    public void insertNewIpFlow(String SA, String DA, String SP, String DP, String PT, String filePath, long lastTime, int frequency){
        //遍历冲突链表 判断该Ip流是否存在
        ImpactLinkNode impactLinkNode = null;
        for(ImpactLinkNode innerImpactLinkNode:impactLinkedList ){
            if(innerImpactLinkNode.SA.equals(SA) && innerImpactLinkNode.DA.equals(DA) && innerImpactLinkNode.SP.equals(SP)
                    && innerImpactLinkNode.DP.equals(DP) && innerImpactLinkNode.PT.equals(PT)){
                impactLinkNode = innerImpactLinkNode;
                break;
            }
        }
        if(impactLinkNode == null){
            //该ip流不存在 则加入头部
            ImpactLinkNode newImpactLinkNode = new ImpactLinkNode(SA,DA,SP,DP,PT,filePath,lastTime,frequency);
            impactLinkedList.addFirst(newImpactLinkNode);
        }else{
            //否则合并两个ip流的pcap文件 修改最后活跃时间 修改访问频度 并将该节点往前移动
            impactLinkNode.filePath = FileUtil.mergePcap(filePath,impactLinkNode.filePath);
            impactLinkNode.lastTime = lastTime;
            impactLinkNode.frequency+=1;
            int index = impactLinkedList.indexOf(impactLinkNode);
            while(index>=1 && impactLinkNode.frequency>= 2*(impactLinkedList.get(index-1).frequency)){
                impactLinkedList.remove(impactLinkNode);
                impactLinkedList.add(index-1,impactLinkNode);
                index-=1;
            }
        }
    }

    /**
     * @description 往冲突链表中插入一个Ip流 此IP流是已经存在的 用于根据冲突链表重构子哈希表时使用 此时插入需要考虑其最后活跃时间 并且不会存在相同节点
     * @param impactLinkNode 该已存在的ip流的冲突链表节点
     * @return void 无返回值
     * @date 2019/4/25
     */
    public void insertExistIpFlow(ImpactLinkNode impactLinkNode){
        //判断此冲突链表是否为空
        if(impactLinkedList.size()==0){
            //将此ip流加入链表首位
            impactLinkedList.addFirst(impactLinkNode);
        }else{
            //此链表不为空 并且由于是重构子hash表 所以必然不会存在相同节点 所以只需先根据访问频度，频度相同时再根据最后活跃时间大的放前面排序即可
            boolean flag = true; //此时该节点还未插入
            for(ImpactLinkNode innerImpactNode:impactLinkedList){
                if(innerImpactNode.frequency<impactLinkNode.frequency){
                    //频度更小，在该节点前插入
                    int index = impactLinkedList.indexOf(innerImpactNode);
                    impactLinkedList.add(index,impactLinkNode);
                    flag=false; //节点已插入
                    break;
                }else if(innerImpactNode.frequency==impactLinkNode.frequency && innerImpactNode.lastTime<impactLinkNode.lastTime){
                    //频度相同，最后活跃时间更晚。在该节点前插入
                    int index = impactLinkedList.indexOf(innerImpactNode);
                    impactLinkedList.add(index,impactLinkNode);
                    flag=false; //节点已插入
                    break;
                }
            }
            if(flag){
                //未插入 应是该链表最后一个节点
                impactLinkedList.addLast(impactLinkNode);
            }
        }
    }

    /**
     * @description  清除冲突链表中超过会话超时计时器 都没活跃的节点
     * @param
     * @return void  无返回值
     * @date 2019/4/28
    */
    public void cleanNodes(){
        for(ImpactLinkNode impactLinkNode : impactLinkedList){
            if(impactLinkNode.lastTime+Parameter.Texp < System.currentTimeMillis()){
                impactLinkedList.remove(impactLinkNode);
            }
        }
    }

    @Override
    public String toString() {
        return "Ic{" +
                "impactLinkedList=" + impactLinkedList +
                '}';
    }
}
