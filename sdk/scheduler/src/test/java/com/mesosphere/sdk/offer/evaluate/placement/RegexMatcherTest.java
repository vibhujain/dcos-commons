package com.mesosphere.sdk.offer.evaluate.placement;

import org.junit.Assert;
import org.junit.Test;

/**
 * Created by gabriel on 1/16/18.
 */
public class RegexMatcherTest {
    @Test
    public void simpleRegex() {
        StringMatcher matcher = RegexMatcher.create("hello-2.*");
        Assert.assertTrue(matcher.matches("hello-2-server"));
    }
}
