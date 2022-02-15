package cn.schoolwow.ssh.domain.stream;

public class DistinguishedEncodingRule {
    /**标签类型*/
    public DERClass derClass;

    /**是否为结构化类型*/
    public boolean structureType;

    /**标签号*/
    public int tagNumber;

    /**内容长度*/
    public int contentLength;

    /**内容*/
    public byte[] content;

    @Override
    public String toString() {
        return "{"
                + "标签类型:" + derClass + ","
                + "是否为结构化类型:" + structureType + ","
                + "标签号:" + tagNumber + ","
                + "内容长度:" + contentLength + ","
                + "内容:" + content
                + "}";
    }
}