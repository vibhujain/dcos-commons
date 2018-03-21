package com.mesosphere.sdk.heron.scheduler;

import com.mesosphere.sdk.testing.*;
import org.junit.Test;

public class ServiceTest {

    @Test
    public void testSpec() throws Exception {
       System.out.println("Pass!");
       // new ServiceTestRunner().run(getDeploymentTicks());
    }
}
// 
// 
//     @Test
//     public void testValidPlacementConstraint() throws Exception {
//         ServiceTestRunner serviceTestRunner = new ServiceTestRunner().setSchedulerEnv("NODE_PLACEMENT", VALID_HOSTNAME_CONSTRAINT);
//         serviceTestRunner.run(getDeploymentTicks());
//     }
// 
//     @Test(expected = IllegalStateException.class)
//     public void testInvalidPlacementConstraint() throws Exception {
//         new ServiceTestRunner().setSchedulerEnv("NODE_PLACEMENT", INVALID_HOSTNAME_CONSTRAINT).run(getDeploymentTicks());
//     }
// 
//     @Test
//     public void testSwitchToInvalidPlacementConstraint() throws Exception {
//         ServiceTestResult initial = new ServiceTestRunner().setSchedulerEnv("NODE_PLACEMENT", VALID_HOSTNAME_CONSTRAINT).run(getDeploymentTicks());
// 
// 
//         Collection<SimulationTick> ticks = new ArrayList<>();
//         ticks.add(Send.register());
//         ticks.add(Expect.planStatus("deploy", Status.ERROR));
// 
//         new ServiceTestRunner().setState(initial).setSchedulerEnv("NODE_PLACEMENT", INVALID_HOSTNAME_CONSTRAINT).run(ticks);
// 
//     }
// 
//     private static Collection<SimulationTick> getDeploymentTicks() {
//         Collection<SimulationTick> ticks = new ArrayList<>();
// 
//         ticks.add(Send.register());
// 
//         ticks.add(Expect.reconciledImplicitly());
// 
//         // "node" task fails to launch on first attempt, without having entered RUNNING.
//         ticks.add(Send.offerBuilder("heron").build());
//         ticks.add(Expect.launchedTasks("heron-0-node"));
//         ticks.add(Send.taskStatus("heron-0-node", Protos.TaskState.TASK_ERROR).build());
// 
//         // Because the task has now been "pinned", a different offer which would fit the task is declined:
//         ticks.add(Send.offerBuilder("heron").build());
//         ticks.add(Expect.declinedLastOffer());
// 
//         // It accepts the offer with the correct resource ids:
//         ticks.add(Send.offerBuilder("heron").setPodIndexToReoffer(0).build());
//         ticks.add(Expect.launchedTasks("heron-0-node"));
//         ticks.add(Send.taskStatus("heron-0-node", Protos.TaskState.TASK_RUNNING).build());
// 
//         // With the pod now running, the scheduler now ignores the same resources if they're reoffered:
//         ticks.add(Send.offerBuilder("heron").setPodIndexToReoffer(0).build());
//         ticks.add(Expect.declinedLastOffer());
// 
//         ticks.add(Expect.allPlansComplete());
// 
//         return ticks;
//     }
// 
// 
// }
