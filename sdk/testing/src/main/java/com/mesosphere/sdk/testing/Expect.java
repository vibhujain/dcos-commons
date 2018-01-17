package com.mesosphere.sdk.testing;

import com.mesosphere.sdk.offer.ResourceUtils;
import com.mesosphere.sdk.offer.evaluate.placement.StringMatcher;
import com.mesosphere.sdk.offer.taskdata.TaskPackingUtils;
import com.mesosphere.sdk.scheduler.plan.Phase;
import com.mesosphere.sdk.scheduler.plan.Plan;
import com.mesosphere.sdk.scheduler.plan.Status;
import com.mesosphere.sdk.scheduler.plan.Step;
import com.mesosphere.sdk.state.StateStore;
import com.mesosphere.sdk.storage.Persister;
import org.apache.mesos.Protos;
import org.apache.mesos.Protos.TaskStatus;
import org.apache.mesos.SchedulerDriver;
import org.junit.Assert;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;


/**
 * A type of {@link SimulationTick} that verifies the scheduler did something.
 */
public interface Expect extends SimulationTick {

    static final Logger LOGGER = LoggerFactory.getLogger(Expect.class);

    /**
     * Verifies that the last offer sent to the scheduler was declined.
     */
    public static Expect declinedLastOffer() {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                ArgumentCaptor<Protos.OfferID> offerIdCaptor = ArgumentCaptor.forClass(Protos.OfferID.class);
                verify(mockDriver, atLeastOnce()).declineOffer(offerIdCaptor.capture(), any());
                Assert.assertEquals(state.getLastOffer().getId().getValue(), offerIdCaptor.getValue().getValue());
            }

            @Override
            public String getDescription() {
                return "Last offer was declined";
            }
        };
    }

    /**
     * Verifies that a pod was launched with exactly the provided task names.
     */
    public static Expect launchedTasks(String... taskNames) {
        return launchedTasks(Arrays.asList(taskNames));
    }

    /**
     * Verifies that a pod was launched with exactly the provided task names.
     */
    public static Expect launchedTasks(Collection<String> taskNames) {
        return launchedTasks(
                new StringMatcher() {
                    @Override
                    public boolean matches(String value) {
                        return taskNames.contains(value);
                    }
                },
                taskNames.size());
    }

    /**
     * Verifies that a pod was launched with exactly the provided task names.
     */
    public static Expect launchedTasks(StringMatcher stringMatcher, int count) {
        return new Expect() {
            // Use this form instead of using ArgumentCaptor.forClass() to avoid problems with typecasting generics:
            @Captor private ArgumentCaptor<Collection<Protos.OfferID>> offerIdsCaptor;
            @Captor private ArgumentCaptor<Collection<Protos.Offer.Operation>> operationsCaptor;

            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                MockitoAnnotations.initMocks(this);
                verify(mockDriver, atLeastOnce())
                        .acceptOffers(offerIdsCaptor.capture(), operationsCaptor.capture(), any());
                Protos.OfferID lastAcceptedOfferId = offerIdsCaptor.getValue().iterator().next();
                Assert.assertEquals(String.format(
                        "Expected last offer with ID %s to be accepted, but last accepted offer was %s",
                        state.getLastOffer().getId().getValue(), lastAcceptedOfferId.getValue()),
                        state.getLastOffer().getId(), lastAcceptedOfferId);
                Collection<String> launchedTaskNames = new ArrayList<>();
                // A single acceptOffers() call may contain multiple LAUNCH/LAUNCH_GROUP operations.
                // We want to ensure they're all counted as a unit when tallying the pod.
                Collection<Protos.TaskInfo> launchedTaskInfos = new ArrayList<>();
                for (Protos.Offer.Operation operation : operationsCaptor.getValue()) {
                    if (operation.getType().equals(Protos.Offer.Operation.Type.LAUNCH)) {
                        // Old-style launch with custom executor
                        launchedTaskNames.addAll(operation.getLaunch().getTaskInfosList().stream()
                                .map(task -> task.getName())
                                .collect(Collectors.toList()));
                        launchedTaskInfos.addAll(operation.getLaunch().getTaskInfosList().stream()
                                .map(task -> TaskPackingUtils.unpack(task))
                                .collect(Collectors.toList()));
                    } else if (operation.getType().equals(Protos.Offer.Operation.Type.LAUNCH_GROUP)) {
                        // New-style launch with default executor
                        launchedTaskNames.addAll(operation.getLaunch().getTaskInfosList().stream()
                                .map(task -> task.getName())
                                .collect(Collectors.toList()));
                        launchedTaskInfos.addAll(operation.getLaunchGroup().getTaskGroup().getTasksList());
                    }
                }
                if (!launchedTaskInfos.isEmpty()) {
                    state.addLaunchedPod(launchedTaskInfos);
                }

                Assert.assertEquals(count, launchedTaskInfos.size());
                Assert.assertEquals(
                        count,
                        launchedTaskNames.stream()
                                .filter(taskName -> stringMatcher.matches(taskName))
                                .count());
            }

            @Override
            public String getDescription() {
                return String.format("%d task(s) matching pattern: %s launched into a pod", count, stringMatcher);
            }
        };
    }

    /**
     * Verifies that the resources for the provided task names have been unreserved.
     */
    public static Expect unreservedTasks(String... taskNames) {
        return unreservedTasks(Arrays.asList(taskNames));
    }

    /**
     * Verifies that the resources for the provided task names have been unreserved.
     */
    public static Expect unreservedTasks(Collection<String> taskNames) {
        return new Expect() {
            // Use this form instead of using ArgumentCaptor.forClass() to avoid problems with typecasting generics:
            @Captor private ArgumentCaptor<Collection<Protos.OfferID>> offerIdsCaptor;
            @Captor private ArgumentCaptor<Collection<Protos.Offer.Operation>> operationsCaptor;

            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                MockitoAnnotations.initMocks(this);
                verify(mockDriver, atLeastOnce())
                        .acceptOffers(offerIdsCaptor.capture(), operationsCaptor.capture(), any());
                Assert.assertEquals(state.getLastOffer().getId(), offerIdsCaptor.getValue().iterator().next());
                Collection<String> expectedResourceIds = taskNames.stream()
                        .map(taskName ->
                                ResourceUtils.getResourceIds(state.getLastLaunchedTask(taskName).getResourcesList()))
                        .flatMap(List::stream)
                        .collect(Collectors.toList());
                Assert.assertFalse(String.format("Expected some resource ids for tasks: %s, got none", taskNames),
                        expectedResourceIds.isEmpty());
                Collection<String> unreservedResourceIds = new ArrayList<>();
                for (Protos.Offer.Operation operation : operationsCaptor.getValue()) {
                    if (operation.getType().equals(Protos.Offer.Operation.Type.DESTROY)) {
                        // Destroy volume(s)
                        unreservedResourceIds.addAll(
                                ResourceUtils.getResourceIds(operation.getDestroy().getVolumesList()));
                    } else if (operation.getType().equals(Protos.Offer.Operation.Type.UNRESERVE)) {
                        // Unreserve resource(s)
                        unreservedResourceIds.addAll(
                                ResourceUtils.getResourceIds(operation.getUnreserve().getResourcesList()));
                    }
                }
                Assert.assertTrue(
                        String.format("Expected unreserved resource ids: %s, got ids: %s",
                                expectedResourceIds, unreservedResourceIds),
                        unreservedResourceIds.containsAll(expectedResourceIds)
                        && expectedResourceIds.containsAll(unreservedResourceIds));
            }

            @Override
            public String getDescription() {
                return String.format("Resources for tasks have been unreserved: %s", taskNames);
            }
        };
    }

    /**
     * Verifies that the specified task was killed.
     */
    public static Expect taskNameKilled(String taskName) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                ArgumentCaptor<Protos.TaskID> taskIdCaptor = ArgumentCaptor.forClass(Protos.TaskID.class);
                verify(mockDriver, atLeastOnce()).killTask(taskIdCaptor.capture());
                Assert.assertEquals(state.getTaskId(taskName).getValue(), taskIdCaptor.getValue().getValue());
            }

            @Override
            public String getDescription() {
                return String.format("Task named %s was killed", taskName);
            }
        };
    }

    public static Expect taskIdKilled(String taskId) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                ArgumentCaptor<Protos.TaskID> taskIdCaptor = ArgumentCaptor.forClass(Protos.TaskID.class);
                verify(mockDriver, atLeastOnce()).killTask(taskIdCaptor.capture());
                Assert.assertEquals(taskId, taskIdCaptor.getValue().getValue());
            }

            @Override
            public String getDescription() {
                return String.format("Task with ID %s was killed", taskId);
            }
        };
    }

    /**
     * Verifies that the specified task was not killed. Note that this applies to the whole simulation as of this point.
     */
    public static Expect taskNameNotKilled(String taskName) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                verify(mockDriver, never()).killTask(state.getTaskId(taskName));
            }

            @Override
            public String getDescription() {
                return String.format("Task named %s was not killed", taskName);
            }
        };
    }

    /**
     * Verifies that an explicit task reconciliation for the task statuses in the provided persister was invoked.
     */
    public static Expect reconciledExplicitly(Persister persisterWithStatuses) {
        // Use a custom comparator for sorting: Protos don't implement Comparable
        final Comparator<Protos.TaskStatus> statusComparator = new Comparator<Protos.TaskStatus>() {
            @Override
            public int compare(TaskStatus o1, TaskStatus o2) {
                return o1.getTaskId().getValue().compareTo(o2.getTaskId().getValue());
            }
        };

        return new Expect() {
            // Use this form instead of using ArgumentCaptor.forClass() to avoid problems with typecasting generics:
            @Captor private ArgumentCaptor<Collection<Protos.TaskStatus>> statusCaptor;

            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                MockitoAnnotations.initMocks(this);
                verify(mockDriver, atLeastOnce()).reconcileTasks(statusCaptor.capture());
                Set<Protos.TaskStatus> expected = new TreeSet<>(statusComparator);
                expected.addAll(new StateStore(persisterWithStatuses).fetchStatuses());
                Set<Protos.TaskStatus> got = new TreeSet<>(statusComparator);
                got.addAll(statusCaptor.getValue());
                Assert.assertEquals(expected, got);
            }

            @Override
            public String getDescription() {
                return String.format("Explicit task reconcile call for statuses: %s",
                        new StateStore(persisterWithStatuses).fetchStatuses().stream()
                                .map(status -> String.format("%s=%s", status.getTaskId().getValue(), status.getState()))
                                .collect(Collectors.toList()));
            }
        };
    }

    /**
     * Verifies that an implicit task reconciliation was invoked.
     */
    public static Expect reconciledImplicitly() {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                verify(mockDriver, atLeastOnce()).reconcileTasks(Collections.emptyList());
            }

            @Override
            public String getDescription() {
                return "Implicit task reconcile call occurred";
            }
        };
    }

    /**
     * Verifies that the scheduler's plans are all complete -- that there's no pending work.
     */
    public static Expect allPlansComplete() {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                Collection<Plan> plans = state.getPlans();
                for (Plan plan : plans) {
                    if (!plan.isComplete()) {
                        Assert.fail(String.format(
                                "%s plan is not complete. Plans: %s",
                                plan.getName(),
                                plans.stream().map(p -> p.toString()).collect(Collectors.toList())));
                    }
                }
            }

            @Override
            public String getDescription() {
                return "All plans complete";
            }
        };
    }

    /**
     * Verifies that the scheduler's deploy plan has the expected status.
     */
    public static Expect deployPlanHasStatus(Status expectedStatus) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) throws AssertionError {
                Plan plan = state.getPlans().stream()
                        .filter(Plan::isDeployPlan)
                        .findAny().get();

                Status actualStatus = plan.getStatus();
                Assert.assertEquals(expectedStatus, actualStatus);
            }

            @Override
            public String getDescription() {
                return String.format("Deploy plan has status: %s", expectedStatus);
            }
        };
    }

    /**
     * Verifies that the scheduler's deploy plan has the expected status.
     */
    public static Expect deployPhaseHasStatus(Status expectedStatus, String phaseName) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) throws AssertionError {
                Plan plan = state.getPlans().stream()
                        .filter(Plan::isDeployPlan)
                        .findAny().get();

                Phase phase = plan.getChildren().stream()
                        .filter(p -> p.getName().equals(phaseName))
                        .findAny().get();

                Status actualStatus = phase.getStatus();
                Assert.assertEquals(expectedStatus, actualStatus);
            }

            @Override
            public String getDescription() {
                return String.format("Deploy phase: %s has status: %s", phaseName, expectedStatus);
            }
        };
    }

    /**
     * Verifies that the scheduler's deploy plan has the expected status.
     */
    public static Expect deployStepHasStatus(Status expectedStatus, String phaseName, String stepName) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) throws AssertionError {
                Plan plan = state.getPlans().stream()
                        .filter(Plan::isDeployPlan)
                        .findAny().get();

                Phase phase = plan.getChildren().stream()
                        .filter(p -> p.getName().equals(phaseName))
                        .findAny().get();

                Step step = phase.getChildren().stream()
                        .filter(s -> s.getName().equals(stepName))
                        .findAny().get();

                Status actualStatus = step.getStatus();
                Assert.assertEquals(expectedStatus, actualStatus);
            }

            @Override
            public String getDescription() {
                return String.format("Deploy phase: %s step: %s has status: %s", phaseName, stepName, expectedStatus);
            }
        };
    }

    /**
     * Verifies that the scheduler's list of tasks in the state store matches the provided set.
     */
    public static Expect knownTasks(Persister persisterWithTasks, String... taskNames) {
        return new Expect() {
            @Override
            public void expect(ClusterState state, SchedulerDriver mockDriver) {
                Set<String> expectedTasks = new HashSet<>(Arrays.asList(taskNames));
                Set<String> tasks = new StateStore(persisterWithTasks).fetchTasks().stream()
                        .map(Protos.TaskInfo::getName)
                        .collect(Collectors.toSet());
                Assert.assertEquals(expectedTasks, tasks);
            }

            @Override
            public String getDescription() {
                return String.format("State store task names: %s",
                        new StateStore(persisterWithTasks).fetchTasks().stream()
                                .map(Protos.TaskInfo::getName)
                                .collect(Collectors.toList()));
            }
        };
    }

    /**
     * Verifies that a certain event had occurred, optionally updating the provided {@link ClusterState} with a result.
     *
     * @param state the simulated cluster's state
     * @param mockDriver a mockito mock which was passed to the Scheduler under test
     * @throws AssertionError containing a descriptive error if the validation failed
     */
    public void expect(ClusterState state, SchedulerDriver mockDriver) throws AssertionError;
}
