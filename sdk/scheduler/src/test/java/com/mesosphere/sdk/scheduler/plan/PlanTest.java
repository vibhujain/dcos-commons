package com.mesosphere.sdk.scheduler.plan;

import com.mesosphere.sdk.config.SerializationUtils;
import com.mesosphere.sdk.http.types.PlanInfo;
import com.mesosphere.sdk.offer.OfferRecommendation;
import com.mesosphere.sdk.scheduler.plan.strategy.CanaryStrategy;
import com.mesosphere.sdk.scheduler.plan.strategy.ParallelStrategy;
import com.mesosphere.sdk.scheduler.plan.strategy.SerialStrategy;
import org.apache.mesos.Protos;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

/**
 * This class tests the {@link Plan} class.
 */
public class PlanTest {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Test
    public void mixedSingleStepPhases() throws IOException {
        Step startingStep = new TestStep("starting", Status.STARTING);
        Step completeStep = new TestStep("complete", Status.COMPLETE);

        Phase startingPhase = new DefaultPhase(
                "starting",
                Arrays.asList(startingStep),
                new SerialStrategy<>(),
                Collections.emptyList());
        Phase completePhase = new DefaultPhase(
                "complete",
                Arrays.asList(completeStep),
                new SerialStrategy<>(),
                Collections.emptyList());

        Plan plan = new DefaultPlan("plan", Arrays.asList(startingPhase, completePhase));
        logger.info(SerializationUtils.toJsonString(PlanInfo.forPlan(plan)));

        Assert.assertEquals(Status.IN_PROGRESS, plan.getStatus());
    }

    @Test
    public void mixedMultiStepPhases() throws IOException {
        Step startingStep = new TestStep("starting", Status.STARTING);
        Step completeStep = new TestStep("complete", Status.COMPLETE);

        Phase inProgressPhase = new DefaultPhase(
                "in_progress",
                Arrays.asList(startingStep, completeStep),
                new SerialStrategy<>(),
                Collections.emptyList());
        Phase completePhase = new DefaultPhase(
                "complete",
                Arrays.asList(completeStep),
                new SerialStrategy<>(),
                Collections.emptyList());

        Plan plan = new DefaultPlan("plan", Arrays.asList(inProgressPhase, completePhase));
        logger.info(SerializationUtils.toJsonString(PlanInfo.forPlan(plan)));

        Assert.assertEquals(Status.IN_PROGRESS, plan.getStatus());
    }

    @Test
    public void mixedCanaryMultiStepPhases() throws IOException {
        Step startingStep = new TestStep("starting", Status.STARTING);
        Step completeStep = new TestStep("complete", Status.COMPLETE);

        List<Step> inProgressSteps = Arrays.asList(completeStep, startingStep, completeStep);
        List<Step> completeSteps = Arrays.asList(completeStep, completeStep);

        Phase inProgressPhase = new DefaultPhase(
                "in_progress",
                inProgressSteps,
                new CanaryStrategy.Generator(new ParallelStrategy<>(), inProgressSteps).generate(),
                Collections.emptyList());
        Phase completePhase = new DefaultPhase(
                "complete",
                completeSteps,
                new CanaryStrategy.Generator(new SerialStrategy<>(), inProgressSteps).generate(),
                Collections.emptyList());

        Plan plan = new DefaultPlan("plan", Arrays.asList(inProgressPhase, completePhase));
        logger.info(SerializationUtils.toJsonString(PlanInfo.forPlan(plan)));

        Assert.assertEquals(Status.IN_PROGRESS, plan.getStatus());
    }

    private static class TestStep implements Step {
        private final UUID id = UUID.randomUUID();
        private final String name;
        private final List<String> errors;

        private Status status;
        private boolean isInterrupted = false;

        public TestStep(String name, Status status) {
            this(name, status, Collections.emptyList());
        }

        public TestStep(String name, Status status, List<String> errors) {
            this.name = name;
            this.status = status;
            this.errors = errors;
        }

        @Override
        public void interrupt() {
            isInterrupted = true;
        }

        @Override
        public void proceed() {
            isInterrupted = false;
        }

        @Override
        public boolean isInterrupted() {
            return isInterrupted;
        }

        @Override
        public UUID getId() {
            return id;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Status getStatus() {
            return status;
        }

        @Override
        public void update(Protos.TaskStatus status) {
            // Intentionally empty
        }

        @Override
        public void restart() {
            status = Status.PENDING;
        }

        @Override
        public void forceComplete() {
            status = Status.COMPLETE;
        }

        @Override
        public List<String> getErrors() {
            return errors;
        }

        @Override
        public Optional<PodInstanceRequirement> start() {
            return getPodInstanceRequirement();
        }

        @Override
        public Optional<PodInstanceRequirement> getPodInstanceRequirement() {
            return Optional.empty();
        }

        @Override
        public void updateOfferStatus(Collection<OfferRecommendation> recommendations) {
            // Intentionally empty
        }
    }
}
