package cn.schoolwow.ssh.layer.transport;

public interface SSHAlgorithm {
    /**
     * 是否匹配该算法
     * @param algorithmName 算法名称
     * */
    boolean matchAlgorithm(String algorithmName);

    /**
     * 支持算法名称列表
     * */
    String[] algorithmNameList();
}