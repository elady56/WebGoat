package org.owasp.webgoat.lessons.deserialization;

import org.owasp.webgoat.container.lessons.Hint;
import org.owasp.webgoat.container.session.Course;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flag;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class SecureObjectInputStream extends ObjectInputStream {

    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {

        List<String> approvedClasses = new ArrayList<String>();
        approvedClasses.add(Course.class.getName());
        approvedClasses.add(Hint.class.getName());
        approvedClasses.add(Email.class.getName());
        approvedClasses.add(Flag.class.getName());
        if (!approvedClasses.contains(osc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization", osc.getName());
        }
        return super.resolveClass(osc);
    }
}
