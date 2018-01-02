package com.mesosphere.sdk.specification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * The ReplacementPolicy defines when a pod should be counted as permanently failed, and therefore replaced.
 */
public class ReplacementPolicy {
    public static final ReplacementPolicy FAILED = new ReplacementPolicy(Trigger.FAILED);
    public static final ReplacementPolicy LOST = new ReplacementPolicy(Trigger.LOST);
    public static final ReplacementPolicy GONE = new ReplacementPolicy(Trigger.GONE);
    public static final ReplacementPolicy MANUAL = new ReplacementPolicy(Trigger.MANUAL);
    public static final ReplacementPolicy DEFAULT = MANUAL;

    private final Trigger trigger;

    /**
     * The trigger defines the threshold at which pods should be replaced.  If pod encounters a Taks
     * which has encountered one of the states enumerated below it is counted as failed.
     *
     * NOTE: The ordering of enum elements is meaningful.
     * See {@link com.mesosphere.sdk.scheduler.recovery.FailureUtils}
     */
    public static enum Trigger {
        FAILED, // [TASK_FAILED]
        LOST,   // [TASK_LOST, TASK_DROPPED, TASK_UNREACHABLE, TASK_UNKNOWN] + FAILED states
        GONE,   // [TASK_GONE, TASK_GONE_BY_OPERATOR] + LOST states
        MANUAL  // Replacement requires external input.  This is the default behavior.
    }

    @JsonCreator
    private ReplacementPolicy(
            @JsonProperty("trigger") Trigger trigger) {
        this.trigger = trigger;
    }

    @JsonProperty("trigger")
    public Trigger getTrigger() {
        return trigger;
    }

    @Override
    public boolean equals(Object o) {
        return EqualsBuilder.reflectionEquals(this, o);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
