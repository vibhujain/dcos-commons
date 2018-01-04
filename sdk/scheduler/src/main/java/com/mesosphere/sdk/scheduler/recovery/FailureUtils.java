package com.mesosphere.sdk.scheduler.recovery;

import com.mesosphere.sdk.offer.TaskException;
import com.mesosphere.sdk.offer.TaskUtils;
import com.mesosphere.sdk.offer.taskdata.TaskLabelReader;
import com.mesosphere.sdk.offer.taskdata.TaskLabelWriter;
import com.mesosphere.sdk.specification.PodInstance;
import com.mesosphere.sdk.specification.ReplacementPolicy;
import com.mesosphere.sdk.specification.ServiceSpec;
import com.mesosphere.sdk.state.ConfigStore;
import com.mesosphere.sdk.state.StateStore;
import com.mesosphere.sdk.state.StateStoreUtils;
import org.apache.mesos.Protos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.stream.Collectors;

/**
 * This class provides utility methods for the handling of failed Tasks.
 */
public class FailureUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(FailureUtils.class);

    private FailureUtils() {
        // do not instantiate
    }

    /**
     * Check if a Task has been marked as permanently failed.
     *
     * @param taskInfo The Task to check for failure.
     * @return True if the Task has been marked, false otherwise.
     */
    public static boolean isPermanentlyFailed(Protos.TaskInfo taskInfo) {
        return new TaskLabelReader(taskInfo).isPermanentlyFailed();
    }

    /**
     * Marks all tasks associated with this pod as failed.
     * This setting will effectively be automatically cleared when the pod is redeployed.
     *
     * @param stateStore the state storage where any updated tasks will be stored
     * @param podInstance the pod whose tasks will be marked as failed
     */
    public static void setPermanentlyFailed(StateStore stateStore, PodInstance podInstance) {
        stateStore.storeTasks(
                StateStoreUtils.fetchPodTasks(stateStore, podInstance).stream()
                        .map(taskInfo -> taskInfo.toBuilder()
                                .setLabels(new TaskLabelWriter(taskInfo).setPermanentlyFailed().toProto())
                                .build())
                        .collect(Collectors.toList()));
    }

    /**
     * Determines whether the given TaskStatus indicates that the Task has failed according to its
     * {@link ReplacementPolicy}.
     */
    public static boolean shouldReplacePod(
            StateStore stateStore,
            ConfigStore<ServiceSpec> configStore,
            Protos.TaskStatus status) {

        ReplacementPolicy replacementPolicy = getReplacementPolicy(stateStore, configStore, status);
        Protos.TaskState state = status.getState();

        switch (state) {
            case TASK_FAILED:
            case TASK_LOST:
            case TASK_DROPPED:
            case TASK_UNREACHABLE:
            case TASK_UNKNOWN:
                return replacementPolicy.getThreshold() == ReplacementPolicy.Threshold.FAILED;
            case TASK_GONE:
            case TASK_GONE_BY_OPERATOR:
                return replacementPolicy.getThreshold().ordinal() <= ReplacementPolicy.Threshold.GONE.ordinal();
            default:
                return false;
        }
    }

    private static ReplacementPolicy getReplacementPolicy(
            StateStore stateStore,
            ConfigStore<ServiceSpec> configStore,
            Protos.TaskStatus status) {

        String taskName = StateStoreUtils.getTaskName(stateStore, status);
        Optional<Protos.TaskInfo> taskInfo = stateStore.fetchTask(taskName);
        if (!taskInfo.isPresent()) {
            LOGGER.error(
                    "Falling back to default replacement policy. Failed to retrive TaskInfo for TaskStatus: {}",
                    status);
            return ReplacementPolicy.DEFAULT;
        }

        ReplacementPolicy replacementPolicy = null;
        try {
            replacementPolicy = TaskUtils.getPodInstance(configStore, taskInfo.get()).getPod().getReplacementPolicy();
        } catch (TaskException e) {
            LOGGER.error(
                    "Falling back to default replacement policy. Failed to retrive pod instance for TaskInfo: {}",
                    taskInfo.get());
            return ReplacementPolicy.DEFAULT;
        }

        return replacementPolicy;
    }
}
