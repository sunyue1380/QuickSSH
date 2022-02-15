package cn.schoolwow.ssh.layer.transport;

public abstract class SSHAlgorithmImpl implements SSHAlgorithm{
    /**匹配算法名称*/
    public String algorithmName;

    @Override
    public boolean matchAlgorithm(String algorithmName) {
        String[] algorithmNameList = algorithmNameList();
        for(String algorithmName1:algorithmNameList){
            if(algorithmName1.equalsIgnoreCase(algorithmName)){
                this.algorithmName = algorithmName;
                return true;
            }
        }
        return false;
    }

    @Override
    public abstract String[] algorithmNameList();
}