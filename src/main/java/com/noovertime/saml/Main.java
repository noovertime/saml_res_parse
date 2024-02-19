package com.noovertime.saml;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.zip.Inflater;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Main {
    public static void main(String[] args) throws Exception {
        // 파일 내용 읽기
        Path targetPath = Path.of("src/main/resources/saml_res_ex.txt");
        if(!targetPath.toFile().isFile()) {
            System.out.println("테스트용 파일 없음 : " + targetPath.toFile().getAbsolutePath());
            return;
        }

        byte[] originBytes = Files.readAllLines(targetPath)
                .stream().collect(Collectors.joining(""))
                .getBytes(StandardCharsets.UTF_8);


        // base64 decoding & inflate
        String xmlStr;
        byte[] base64DecodedBytes = Base64.getMimeDecoder().decode(originBytes);

        try {
            byte[] inflatedData = new byte[5 * 1024]; // 5K
            Inflater inflater = new Inflater(true);
            inflater.setInput(base64DecodedBytes);
            int inflatedBytesLength = inflater.inflate(inflatedData);
            inflater.end();
            // XML 문자열로 변환
            xmlStr = new String(inflatedData, 0, inflatedBytesLength);
        }
        catch(Exception ex) {
            // inflate 실패는 inflate 없이 base64인코딩된 것으로 처리
            xmlStr = new String(base64DecodedBytes);
        }

        // signature 검증
        if(!checkSignagure(xmlStr)) {
            System.out.println("Signature 검증 실패");
            return;
        }

        // data추출 확인
        extract(xmlStr);
    }

    private static boolean checkSignagure(String samlResXml) throws Exception {
        // XML 문서 파싱
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(samlResXml.getBytes()));

        // Signature 엘리먼트 꺼내기
        NodeList signatureList = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
        Element signatureElement = (Element) signatureList.item(0);

        // Create a DOMValidateContext and specify a KeySelector
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), signatureElement);
        // sha1을 허용하기 위해 secure validation 기능 끔
        valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);

        // ID 참조가 포함된 문서를 위한 ID 정리
        List<Node> idNodeList = new ArrayList<>();
        findElementsWithID(idNodeList, doc.getDocumentElement());
        if(!idNodeList.isEmpty()) {
            for(Node node : idNodeList) {
                valContext.setIdAttributeNS( (Element) node, null, "ID");
            }
        }

        // Unmarshal the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // signature 검증결과 반환
        return signature.validate(valContext);
    }

    private static void findElementsWithID(List sumNodeList, Node node) {
        NodeList childNodeList = node.getChildNodes();

        for(int i = 0; i < childNodeList.getLength(); i++) {
            Node child = childNodeList.item(i);
            if(child.getNodeType() == Node.ELEMENT_NODE) {
                NamedNodeMap attributes = child.getAttributes();
                Node idAttribute = attributes.getNamedItem("ID");
                if(idAttribute != null) {
                    sumNodeList.add(child);
                }

                // 재귀
                findElementsWithID(sumNodeList, child);
            }
        }
    }


    private static void extract(String samlResXml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(samlResXml.getBytes(StandardCharsets.UTF_8)));

        //
        System.out.println("issuer : " + extractIssuer(doc));
        System.out.println("nameId : " + extractNameID(doc));
        System.out.println("authnContextClassRef : " + extractAuthnContextClassRef(doc));
    }

    static class X509KeySelector extends KeySelector {
        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context)
                throws KeySelectorException {

            // XML 내에서 공개키 (X509Certificate) 찾기
            Optional<PublicKey> keyOp = keyInfo.getContent().stream()
                    .filter(info -> info instanceof X509Data)
                    .flatMap(info -> ((X509Data) info).getContent().stream())
                    .filter(o -> o instanceof X509Certificate)
                    .map(o -> ((X509Certificate) o).getPublicKey())
                    .findFirst();

            if(keyOp.isEmpty()) {
                throw new KeySelectorException("key없음");
            }

            return () -> keyOp.get();
        }
    }

    private static String extractAuthnContextClassRef(Document doc) {
        Element authnContextClassRefElement = (Element) doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContextClassRef").item(0);
        return authnContextClassRefElement.getTextContent();
    }

    // Extract Issuer from the SAML Response
    private static String extractIssuer(Document doc) {
        Element issuerElement = (Element) doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer").item(0);
        return issuerElement.getTextContent();
    }

    // Extract NameID from the SAML Response
    private static String extractNameID(Document doc) {
        Element nameIDElement = (Element) doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID").item(0);
        return nameIDElement.getTextContent();
    }

}
