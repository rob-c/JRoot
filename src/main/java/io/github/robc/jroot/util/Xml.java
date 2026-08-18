package io.github.robc.jroot.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import io.github.robc.jroot.XrdException;

/**
 * The JDK's XML parser, configured so that a document from the network
 * cannot make it fetch anything or expand anything.
 *
 * <p>Two things arrive as XML here — a WebDAV {@code PROPFIND} multistatus
 * and a metalink — and both come from wherever the URL pointed, so both are
 * parsed with external entities, DTDs and XInclude all switched off. The
 * navigation helpers work on local names, since a document is free to bind
 * its namespaces to whatever prefixes it likes.
 */
public final class Xml {

    private Xml() {
    }

    /** Parse {@code body}, blaming {@code what} if it will not parse. */
    public static Document parse(byte[] body, Object what) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) ->
                    new InputSource(new StringReader("")));
            return builder.parse(new ByteArrayInputStream(body));
        } catch (ParserConfigurationException e) {
            throw new XrdException("the JDK XML parser refused a safe configuration", e);
        } catch (SAXException | IOException e) {
            throw new XrdException(what + " returned unreadable XML: " + e.getMessage(), e);
        }
    }

    /** The first child element called {@code name}, or null. */
    public static Element child(Element parent, String name) {
        List<Element> found = children(parent, name);
        return found.isEmpty() ? null : found.get(0);
    }

    /** Every child element called {@code name}, whatever prefix it wore. */
    public static List<Element> children(Element parent, String name) {
        List<Element> out = new ArrayList<>();
        if (parent == null) {
            return out;
        }
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element element && name.equals(localName(element))) {
                out.add(element);
            }
        }
        return out;
    }

    /** Every element called {@code name} anywhere below {@code root}. */
    public static List<Element> descendants(Element root, String name) {
        List<Element> out = new ArrayList<>();
        if (root == null) {
            return out;
        }
        NodeList nodes = root.getElementsByTagName("*");
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i) instanceof Element element && name.equals(localName(element))) {
                out.add(element);
            }
        }
        return out;
    }

    /** An element's text, stripped; the empty string when there is none. */
    public static String text(Element element) {
        return element == null ? "" : element.getTextContent().strip();
    }

    public static String localName(Element element) {
        String local = element.getLocalName();
        return local != null ? local : element.getNodeName();
    }
}
