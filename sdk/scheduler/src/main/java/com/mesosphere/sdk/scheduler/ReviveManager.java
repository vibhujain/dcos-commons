package com.mesosphere.sdk.scheduler;

import com.google.common.eventbus.EventBus;
import com.mesosphere.sdk.offer.TaskUtils;
import com.mesosphere.sdk.scheduler.plan.PlanCoordinator;
import com.mesosphere.sdk.specification.ServiceSpec;
import com.mesosphere.sdk.state.ConfigStore;
import com.mesosphere.sdk.state.StateStore;
import org.apache.mesos.SchedulerDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * This class monitors all plans and revives offers when appropriate.
 */
public class ReviveManager {
    public static final int REVIVE_INTERVAL_S = 5;
    public static final int REVIVE_DELAY_S = 5;

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ScheduledExecutorService plansMonitor = Executors.newScheduledThreadPool(1);
    private final SchedulerDriver driver;
    private final PlanCoordinator planCoordinator;
    private final StateStore stateStore;

    private final ConfigStore<ServiceSpec> configStore;
    private Set<String> candidates = Collections.emptySet();

    /**
     * The states of the suppress/revive state machine.
     */
    public enum State {
        INITIAL,
        WAITING_FOR_OFFER,
        REVIVED
    }

    public ReviveManager(
            StateStore stateStore,
            ConfigStore<ServiceSpec> configStore,
            SchedulerDriver driver,
            EventBus eventBus,
            PlanCoordinator planCoordinator) {
        this(
                stateStore,
                configStore,
                driver,
                eventBus,
                planCoordinator,
                REVIVE_DELAY_S,
                REVIVE_INTERVAL_S);
    }

    public ReviveManager(
            StateStore stateStore,
            ConfigStore<ServiceSpec> configStore,
            SchedulerDriver driver,
            EventBus eventBus,
            PlanCoordinator planCoordinator,
            int pollDelay,
            int pollInterval) {

        this.stateStore = stateStore;
        this.configStore = configStore;
        this.driver = driver;
        this.planCoordinator = planCoordinator;
        eventBus.register(this);
        plansMonitor.scheduleAtFixedRate(
                new Runnable() {
                    @Override
                    public void run() {
                        revive();
                    }
                },
                pollDelay,
                pollInterval,
                TimeUnit.SECONDS);

        logger.info(
                "Monitoring these plans for suppress/revive: {}",
                planCoordinator.getPlanManagers().stream()
                        .map(planManager -> planManager.getPlan().getName())
                        .collect(Collectors.toList()));
    }

    private void revive() {
        Set<String> newCandidates = planCoordinator.getCandidates().stream()
                .filter(step -> step.getPodInstanceRequirement().isPresent())
                .map(step -> step.getPodInstanceRequirement().get())
                .flatMap(req -> TaskUtils.getTaskNames(req.getPodInstance()).stream())
                .collect(Collectors.toSet());
        logger.debug("Got candidates: {}", newCandidates);

        newCandidates.removeAll(candidates);

        logger.debug("Old candidates: {}", candidates);
        logger.debug("New candidates: {}", newCandidates);

        if (newCandidates.isEmpty()) {
            logger.debug("No new candidates detected, no need to revive.");
        } else {
            candidates = newCandidates;
            logger.info("Reviving offers.");
            driver.reviveOffers();
        }
    }
}
